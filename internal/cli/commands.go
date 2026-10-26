// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/go-wasmcontainers/relay/firewall"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/tlsca"
)

func table(w io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(w, 0, 4, 2, ' ', 0) }

// ------------------------------------------------------------------- class

func classCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "class", Short: "Create, list and manage classes"}
	var cidr, domain, tmpl string
	var bits uint32
	var allow []string
	var requireID bool
	create := &cobra.Command{Use: "create NAME", Short: "Create a class and print its join code", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t := v1.Template_TEMPLATE_ISOLATED
			switch tmpl {
			case "isolated", "":
			case "neutron", "neutron-default":
				t = v1.Template_TEMPLATE_NEUTRON_DEFAULT
			default:
				return fmt.Errorf("--template %q: isolated or neutron", tmpl)
			}
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			cls, err := c.cls.CreateClass(ctx, &v1.CreateClassRequest{Name: args[0], Cidr: cidr, SessionBits: bits,
				DnsDomain: domain, Template: t, Allowed: allow, RequireIdentity: requireID})
			if err != nil {
				return err
			}
			printClass(cmd.OutOrStdout(), cls)
			return nil
		}}
	fl := create.Flags()
	fl.StringVar(&cidr, "cidr", "", "class network (default 10.42.0.0/16)")
	fl.Uint32Var(&bits, "session-bits", 0, "prefix length of each session's subnet (default 24)")
	fl.StringVar(&domain, "domain", "", `DNS domain (default "class")`)
	fl.StringVar(&tmpl, "template", "isolated", "default group: isolated (no ingress) or neutron (Neutron's default)")
	fl.StringSliceVar(&allow, "allow", nil, "who may join with OpenID Connect: sub:<id>, email:<address>, group:<name>")
	fl.BoolVar(&requireID, "require-identity", false, "joining needs an OpenID Connect sign-in")

	list := &cobra.Command{Use: "list", Short: "List classes", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			res, err := c.cls.ListClasses(ctx, &v1.ListClassesRequest{})
			if err != nil {
				return err
			}
			tw := table(cmd.OutOrStdout())
			fmt.Fprintln(tw, "ID\tNAME\tJOIN CODE\tNETWORK\tTEMPLATE")
			for _, cl := range res.Classes {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", cl.Id, cl.Name, groupCode(cl.JoinCode), cl.Network.GetCidr(), templateName(cl.Template))
			}
			return tw.Flush()
		}}
	del := &cobra.Command{Use: "delete CLASS", Short: "Delete a class, its sessions and what the relay knows of its students", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			_, err = c.cls.DeleteClass(ctx, &v1.DeleteClassRequest{Id: args[0]})
			return err
		}}
	rotate := &cobra.Command{Use: "rotate-code CLASS", Short: "Draw a new join code (the old one stops admitting)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			cls, err := c.cls.RotateJoinCode(ctx, &v1.RotateJoinCodeRequest{ClassId: args[0]})
			if err != nil {
				return err
			}
			printClass(cmd.OutOrStdout(), cls)
			return nil
		}}
	sessions := &cobra.Command{Use: "sessions CLASS", Short: "List a class's sessions", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			res, err := c.cls.ListSessions(ctx, &v1.ListSessionsRequest{ClassId: args[0]})
			if err != nil {
				return err
			}
			tw := table(cmd.OutOrStdout())
			fmt.Fprintln(tw, "LABEL\tNAME\tSUBNET\tCONNECTED\tID")
			for _, s := range res.Sessions {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\n", s.Label, s.DisplayName, s.Subnet, s.Connected, s.Id)
			}
			return tw.Flush()
		}}
	kick := &cobra.Command{Use: "kick CLASS SESSION", Short: "End a session (label or id)", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			_, err = c.cls.KickSession(ctx, &v1.KickSessionRequest{ClassId: args[0], Session: args[1]})
			return err
		}}
	cmd.AddCommand(create, list, del, rotate, sessions, kick)
	return cmd
}

func groupCode(c string) string {
	if len(c) == 10 {
		return c[:5] + "-" + c[5:]
	}
	return c
}

func templateName(t v1.Template) string {
	if t == v1.Template_TEMPLATE_NEUTRON_DEFAULT {
		return "neutron"
	}
	return "isolated"
}

func printClass(w io.Writer, c *v1.Class) {
	fmt.Fprintf(w, "class     %s (%s)\njoin code %s\nnetwork   %s, /%d per session, domain .%s\ntemplate  %s\n",
		c.Name, c.Id, groupCode(c.JoinCode), c.Network.GetCidr(), c.Network.GetSessionBits(), c.Network.GetDnsDomain(), templateName(c.Template))
}

// ---------------------------------------------------------- security groups

func sgCmd(g *globals) *cobra.Command {
	var class string
	cmd := &cobra.Command{Use: "sg", Short: "Security groups"}
	cmd.PersistentFlags().StringVar(&class, "class", "", "class id")
	list := &cobra.Command{Use: "list", Short: "List groups and their rules", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			res, err := c.sg.ListSecurityGroups(ctx, &v1.ListSecurityGroupsRequest{ClassId: class})
			if err != nil {
				return err
			}
			tw := table(cmd.OutOrStdout())
			fmt.Fprintln(tw, "GROUP\tRULE\tDIRECTION\tPROTOCOL\tPORTS\tREMOTE")
			for _, sg := range res.SecurityGroups {
				state := ""
				if !sg.Stateful {
					state = " (stateless)"
				}
				if len(sg.Rules) == 0 {
					fmt.Fprintf(tw, "%s%s\t-\t\t\t\t\n", sg.Name, state)
				}
				for _, r := range sg.Rules {
					fmt.Fprintf(tw, "%s%s\t%s\t%s\n", sg.Name, state, r.Id, ruleText(r, res.SecurityGroups))
				}
			}
			return tw.Flush()
		}}
	var stateless bool
	var desc string
	create := &cobra.Command{Use: "create NAME", Short: "Create an empty group (it allows nothing)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			sg, err := c.sg.CreateSecurityGroup(ctx, &v1.CreateSecurityGroupRequest{ClassId: class, Name: args[0], Description: desc, Stateless: stateless})
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), sg.Id)
			return nil
		}}
	create.Flags().BoolVar(&stateless, "stateless", false, "no connection tracking: replies need their own rules")
	create.Flags().StringVar(&desc, "description", "", "description")
	del := &cobra.Command{Use: "delete GROUP", Short: "Delete a group no port uses", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			_, err = c.sg.DeleteSecurityGroup(ctx, &v1.DeleteSecurityGroupRequest{ClassId: class, Group: args[0]})
			return err
		}}
	cmd.AddCommand(list, create, del)
	return cmd
}

func ruleText(r *v1.SecurityGroupRule, groups []*v1.SecurityGroup) string {
	dir := "ingress"
	if r.Direction == v1.Direction_DIRECTION_EGRESS {
		dir = "egress"
	}
	proto := firewall.Protocol(r.Protocol).String()
	ports := "any"
	if r.PortRangeMin != 0 || r.PortRangeMax != 0 {
		if r.PortRangeMin == r.PortRangeMax {
			ports = fmt.Sprint(r.PortRangeMin)
		} else {
			ports = fmt.Sprintf("%d-%d", r.PortRangeMin, r.PortRangeMax)
		}
	}
	remote := "any"
	switch rem := r.Remote.(type) {
	case *v1.SecurityGroupRule_RemoteIpPrefix:
		remote = rem.RemoteIpPrefix
	case *v1.SecurityGroupRule_RemoteGroupId:
		remote = "group " + rem.RemoteGroupId
		for _, g := range groups {
			if g.Id == rem.RemoteGroupId {
				remote = "group " + g.Name
			}
		}
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s", dir, proto, ports, remote)
}

// --------------------------------------------------------------------- rules

func ruleCmd(g *globals) *cobra.Command {
	var class string
	cmd := &cobra.Command{Use: "rule", Short: "Security group rules"}
	cmd.PersistentFlags().StringVar(&class, "class", "", "class id")
	var ingress, egress, logIt bool
	var proto, ports, remoteIP, remoteGroup, desc string
	add := &cobra.Command{Use: "add GROUP", Short: "Allow a flow (rules only allow)", Args: cobra.ExactArgs(1),
		Example: "  wctr-relay rule add web --class c-1 --ingress --proto tcp --port 80 --remote-group default",
		RunE: func(cmd *cobra.Command, args []string) error {
			if ingress == egress {
				return errors.New("give --ingress or --egress")
			}
			p, err := firewall.ParseProtocol(proto)
			if err != nil {
				return err
			}
			lo, hi, err := firewall.ParsePortRange(ports)
			if err != nil {
				return err
			}
			if p == firewall.Any && (lo != 0 || hi != 0) {
				return errors.New("--port needs --proto tcp or udp")
			}
			r := &v1.SecurityGroupRule{Direction: v1.Direction_DIRECTION_INGRESS, Protocol: v1.Protocol(p),
				PortRangeMin: uint32(lo), PortRangeMax: uint32(hi), Description: desc, Log: logIt}
			if egress {
				r.Direction = v1.Direction_DIRECTION_EGRESS
			}
			switch {
			case remoteIP != "" && remoteGroup != "":
				return errors.New("--remote-ip or --remote-group, not both")
			case remoteIP != "":
				r.Remote = &v1.SecurityGroupRule_RemoteIpPrefix{RemoteIpPrefix: remoteIP}
			case remoteGroup != "":
				r.Remote = &v1.SecurityGroupRule_RemoteGroupId{RemoteGroupId: remoteGroup}
			}
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			res, err := c.sg.CreateRule(ctx, &v1.CreateRuleRequest{ClassId: class, Group: args[0], Rule: r})
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), res.Id)
			return nil
		}}
	fl := add.Flags()
	fl.BoolVar(&ingress, "ingress", false, "traffic arriving at the group's ports")
	fl.BoolVar(&egress, "egress", false, "traffic leaving the group's ports")
	fl.StringVar(&proto, "proto", "any", "tcp, udp, icmp or any")
	fl.StringVar(&ports, "port", "", "port or range (80, 8000-8080); for icmp, the type")
	fl.StringVar(&remoteIP, "remote-ip", "", "remote address prefix (10.42.0.0/24)")
	fl.StringVar(&remoteGroup, "remote-group", "", "remote security group (name or id)")
	fl.StringVar(&desc, "description", "", "description")
	fl.BoolVar(&logIt, "log", false, "mark the rule as logged")
	del := &cobra.Command{Use: "delete RULE", Aliases: []string{"del"}, Short: "Remove a rule; flows only it allowed are reset", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			_, err = c.sg.DeleteRule(ctx, &v1.DeleteRuleRequest{ClassId: class, RuleId: args[0]})
			return err
		}}
	cmd.AddCommand(add, del)
	return cmd
}

// --------------------------------------------------------------------- ports

func portCmd(g *globals) *cobra.Command {
	var class, session string
	cmd := &cobra.Command{Use: "port", Short: "Ports: the containers on the class network"}
	cmd.PersistentFlags().StringVar(&class, "class", "", "class id")
	list := &cobra.Command{Use: "list", Short: "List ports", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			res, err := c.port.ListPorts(ctx, &v1.ListPortsRequest{ClassId: class, Session: session})
			if err != nil {
				return err
			}
			tw := table(cmd.OutOrStdout())
			fmt.Fprintln(tw, "NAME\tADDRESS\tGROUPS\tPORT SECURITY\tID")
			for _, p := range res.Ports {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\n", p.DnsName, p.Ip, strings.Join(p.SecurityGroups, ","), p.PortSecurityEnabled, p.Id)
			}
			return tw.Flush()
		}}
	list.Flags().StringVar(&session, "student", "", "only this session (label or id)")
	var groups []string
	var portSec string
	set := &cobra.Command{Use: "set PORT", Short: "Set a port's groups (--sg) or port security", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &v1.UpdatePortRequest{ClassId: class, Port: args[0]}
			if cmd.Flags().Changed("sg") {
				req.SecurityGroups, req.SetSecurityGroups = groups, true
			}
			switch portSec {
			case "":
			case "on":
				t := true
				req.PortSecurityEnabled = &t
			case "off":
				f := false
				req.PortSecurityEnabled = &f
			default:
				return errors.New("--port-security on or off")
			}
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			p, err := c.port.UpdatePort(ctx, req)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s groups=%s port-security=%v\n", p.DnsName, p.Ip, strings.Join(p.SecurityGroups, ","), p.PortSecurityEnabled)
			return nil
		}}
	set.Flags().StringSliceVar(&groups, "sg", nil, "security groups (replaces the list)")
	set.Flags().StringVar(&portSec, "port-security", "", "on or off (off: no filtering at all)")
	cmd.AddCommand(list, set)
	return cmd
}

// --------------------------------------------------------------------- flows

func flowsCmd(g *globals) *cobra.Command {
	var class, session string
	var denyOnly, follow bool
	var backlog uint32
	cmd := &cobra.Command{Use: "flows", Short: "Show the flow log (--follow to stream it)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			st, err := c.flows.WatchFlows(ctx, &v1.WatchFlowsRequest{ClassId: class, DenyOnly: denyOnly, Session: session, Backlog: backlog})
			if err != nil {
				return err
			}
			defer st.Close()
			out := cmd.OutOrStdout()
			if !follow {
				// The backlog, then stop at the first quiet moment.
				go func() {
					<-time.After(500 * time.Millisecond)
					st.Close()
				}()
			}
			for {
				e, err := st.Receive()
				if err != nil {
					if follow && !errors.Is(err, io.EOF) && ctx.Err() == nil {
						return err
					}
					return nil
				}
				fmt.Fprintln(out, flowLine(e))
			}
		}}
	cmd.Flags().StringVar(&class, "class", "", "class id")
	cmd.Flags().StringVar(&session, "student", "", "only flows touching this session")
	cmd.Flags().BoolVar(&denyOnly, "deny-only", false, "only refused and revoked flows")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep streaming")
	cmd.Flags().Uint32Var(&backlog, "backlog", 50, "recent events first (at most 1000)")
	return cmd
}

func flowLine(e *v1.FlowEvent) string {
	t := time.Unix(0, e.TimeUnixNano).Format("15:04:05")
	verdict := strings.TrimPrefix(e.Verdict.String(), "VERDICT_")
	s := fmt.Sprintf("%s %-7s %s %s -> %s", t, verdict, firewall.Protocol(e.Protocol), e.Src, e.Dst)
	if e.EgressRuleId != "" || e.IngressRuleId != "" {
		s += fmt.Sprintf(" rules=%s,%s", e.EgressRuleId, e.IngressRuleId)
	}
	if e.BytesOut != 0 || e.BytesIn != 0 {
		s += fmt.Sprintf(" bytes=%d/%d", e.BytesOut, e.BytesIn)
	}
	if e.Reason != "" {
		s += " (" + e.Reason + ")"
	}
	return s
}

// -------------------------------------------------------------------- explain

func explainCmd(g *globals) *cobra.Command {
	var class string
	cmd := &cobra.Command{Use: "explain SRC DST PROTO/PORT", Short: "Say what the firewall would decide",
		Example: "  wctr-relay explain --class c-1 bob/curl alice/web tcp/80", Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			ps, port, _ := strings.Cut(args[2], "/")
			p, err := firewall.ParseProtocol(ps)
			if err != nil {
				return err
			}
			lo, _, err := firewall.ParsePortRange(port)
			if err != nil {
				return err
			}
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			e, err := c.sg.ExplainFlow(ctx, &v1.ExplainFlowRequest{ClassId: class, Src: args[0], Dst: args[1], Protocol: v1.Protocol(p), DstPort: uint32(lo)})
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), flowLine(e))
			return nil
		}}
	cmd.Flags().StringVar(&class, "class", "", "class id")
	return cmd
}

// ------------------------------------------------------------------------ ca

func caCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "ca", Short: "The internal CA"}
	export := &cobra.Command{Use: "export", Short: "Print the root certificate (PEM) to install on the class's machines", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := g.dir()
			if err != nil {
				return err
			}
			ca, err := tlsca.Load(d.CA())
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(ca.RootPEM())
			return err
		}}
	fp := &cobra.Command{Use: "fingerprint", Short: "Print the root's SHA-256 fingerprint", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := g.dir()
			if err != nil {
				return err
			}
			ca, err := tlsca.Load(d.CA())
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), ca.Fingerprint())
			return nil
		}}
	var names, ips []string
	rotate := &cobra.Command{Use: "rotate", Short: "Replace the CA (machines must trust the new root)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := g.dir()
			if err != nil {
				return err
			}
			addrs, err := parseIPs(ips)
			if err != nil {
				return err
			}
			if err := tlsca.Rotate(d.CA(), names, addrs); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "new CA in", d.CA(), "- restart serve")
			return nil
		}}
	rotate.Flags().StringSliceVar(&names, "name", nil, "DNS name (repeatable)")
	rotate.Flags().StringSliceVar(&ips, "ip", nil, "IP address (repeatable)")
	cmd.AddCommand(export, fp, rotate)
	return cmd
}

// ------------------------------------------------------------------- teacher

func teacherCmd(g *globals) *cobra.Command {
	var class, out string
	cmd := &cobra.Command{Use: "teacher-session", Short: "Write a session token for the teacher's own containers to a 0600 file", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" {
				return errors.New("--out FILE: the token is a secret, it is written to a file, not printed")
			}
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			j, err := c.join.TeacherSession(ctx, &v1.TeacherSessionRequest{ClassId: class})
			if err != nil {
				return err
			}
			f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			if _, err := f.WriteString(j.SessionToken + "\n"); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "teacher session %s (%s) token in %s\n", j.Session.Label, j.Session.Subnet, out)
			return nil
		}}
	cmd.Flags().StringVar(&class, "class", "", "class id")
	cmd.Flags().StringVar(&out, "out", "", "file to write the token to (0600)")
	return cmd
}
