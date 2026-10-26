// SPDX-License-Identifier: BSD-3-Clause

// Package cli is the wctr-relay command line: the relay daemon (serve) and
// the teacher's client of its control API, in one cobra tree.
package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/spf13/cobra"

	"github.com/go-wasmcontainers/relay/gen/relayv1/relayv1connect"
	"github.com/go-wasmcontainers/relay/internal/statedir"
)

// Version is set at build time (-ldflags -X).
var Version = "devel"

type globals struct {
	stateDir  string
	server    string // admin URL; empty: the state directory's socket
	tokenFile string
	caFile    string
	adminSock string // --admin-socket; empty: admin.sock in the state directory
}

// RootCmd builds the command tree.
func RootCmd() *cobra.Command {
	g := &globals{}
	root := &cobra.Command{
		Use:   "wctr-relay",
		Short: "The classroom relay and firewall for WASI containers",
		Long: "wctr-relay connects the WASI containers of a class's browsers through one relay that is also a firewall,\n" +
			"with security groups modelled on OpenStack Neutron. `serve` runs it; the other commands manage it.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.StringVar(&g.stateDir, "state-dir", "", "state directory (default: <user config dir>/wctr-relay)")
	pf.StringVar(&g.server, "server", "", "admin API URL of a remote relay (default: the local admin socket)")
	pf.StringVar(&g.tokenFile, "token-file", "", "file holding the admin token for --server (0600)")
	pf.StringVar(&g.caFile, "ca-file", "", "PEM root to trust for --server")
	pf.StringVar(&g.adminSock, "admin-socket", "", "admin socket path (default: admin.sock in the state directory; at most 103 bytes on macOS, 107 on Linux)")
	root.AddCommand(versionCmd(), initCmd(g), serveCmd(g), classCmd(g), sgCmd(g), ruleCmd(g), portCmd(g),
		flowsCmd(g), explainCmd(g), caCmd(g), teacherCmd(g), flowMapCmd(g))
	return root
}

func versionCmd() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print the version", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "wctr-relay", Version)
			return nil
		}}
}

func (g *globals) dir() (statedir.Dir, error) {
	if g.stateDir != "" {
		return statedir.Dir(g.stateDir), nil
	}
	return statedir.Default()
}

// client is the control-API client the commands use: the local admin socket
// (its file permissions are the credential), or --server with a token file.
type client struct {
	cls   relayv1connect.ClassServiceClient
	join  relayv1connect.JoinServiceClient
	sg    relayv1connect.SecurityGroupServiceClient
	port  relayv1connect.PortServiceClient
	flows relayv1connect.FlowLogServiceClient
	fmap  relayv1connect.FlowMapServiceClient
}

type bearerRT struct {
	base  http.RoundTripper
	token string
}

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func (g *globals) client() (*client, error) {
	var hc *http.Client
	base := g.server
	if base == "" {
		sock, err := g.adminSocket()
		if err != nil {
			return nil, err
		}
		hc = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, "unix", sock)
		}}}
		base = "http://wctr-relay"
	} else {
		if !strings.HasPrefix(base, "https://") && !isLoopbackURL(base) {
			return nil, errors.New("--server must be https (or loopback)")
		}
		if g.tokenFile == "" {
			return nil, errors.New("--server needs --token-file (the token is never a flag value)")
		}
		tok, err := statedir.ReadSecret(g.tokenFile)
		if err != nil {
			return nil, err
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		if g.caFile != "" {
			pool, err := loadPool(g.caFile)
			if err != nil {
				return nil, err
			}
			tr.TLSClientConfig.RootCAs = pool
		}
		hc = &http.Client{Transport: bearerRT{base: tr, token: tok}}
	}
	c := connect.NewClient(connecthttp.NewTransport(hc, base))
	return &client{
		cls: relayv1connect.NewClassServiceClient(c), join: relayv1connect.NewJoinServiceClient(c),
		sg: relayv1connect.NewSecurityGroupServiceClient(c), port: relayv1connect.NewPortServiceClient(c),
		fmap:  relayv1connect.NewFlowMapServiceClient(c),
		flows: relayv1connect.NewFlowLogServiceClient(c),
	}, nil
}

func isLoopbackURL(u string) bool {
	rest, ok := strings.CutPrefix(u, "http://")
	if !ok {
		return false
	}
	host := strings.SplitN(rest, "/", 2)[0]
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

func cmdCtx(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	return context.WithTimeout(cmd.Context(), 30*time.Second)
}

// --------------------------------------------------------------------- init

func initCmd(g *globals) *cobra.Command {
	var names []string
	var ips []string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the state directory: admin token, signing keys, and the internal CA for --name/--ip",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := g.dir()
			if err != nil {
				return err
			}
			created, err := d.Init()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if created {
				fmt.Fprintf(out, "state directory %s initialised (admin token in %s)\n", d, d.TokenFile())
			} else {
				fmt.Fprintf(out, "state directory %s already initialised\n", d)
			}
			if len(names) > 0 || len(ips) > 0 {
				addrs, err := parseIPs(ips)
				if err != nil {
					return err
				}
				if err := initCA(d, names, addrs); err != nil {
					return err
				}
				fmt.Fprintf(out, "internal CA created in %s: install %s on the class's machines\n", d.CA(), filepath.Join(d.CA(), "ca.crt"))
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&names, "name", nil, "DNS name of the relay, for the internal CA (repeatable)")
	cmd.Flags().StringSliceVar(&ips, "ip", nil, "IP address of the relay, for the internal CA (repeatable)")
	return cmd
}

func parseIPs(ss []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("--ip %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func printErr(w io.Writer, err error) {
	if ce := new(connect.Error); errors.As(err, &ce) {
		fmt.Fprintf(w, "wctr-relay: %s\n", ce.Message())
		return
	}
	fmt.Fprintf(w, "wctr-relay: %v\n", err)
}

// Main runs the command line with args and returns the exit status.
func Main(args []string, stdout, stderr io.Writer) int {
	root := RootCmd()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.Execute(); err != nil {
		printErr(stderr, err)
		return 1
	}
	return 0
}
