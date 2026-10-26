// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

func flowMapCmd(g *globals) *cobra.Command {
	var class, base string
	cmd := &cobra.Command{
		Use:   "flowmap",
		Short: "Print the link to the class's live flow map (a read-only ticket, 12 hours)",
		Long: "Print the link that opens the live flow map of a class in a browser. The link carries a read-only\n" +
			"ticket in its fragment (after #), which the browser never sends to a server; it allows watching the\n" +
			"class's flow map and nothing else, for 12 hours. Show it on the projector, do not share it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if class == "" {
				return errors.New("--class is required")
			}
			u, err := url.Parse(base)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return errors.New("--url must be the relay's https address, e.g. https://relay.local:8443")
			}
			c, err := g.client()
			if err != nil {
				return err
			}
			ctx, cancel := cmdCtx(cmd)
			defer cancel()
			t, err := c.fmap.FlowMapTicket(ctx, &v1.FlowMapTicketRequest{ClassId: class})
			if err != nil {
				return err
			}
			frag := url.Values{"class": {class}, "ticket": {t.Ticket}}.Encode()
			fmt.Fprintf(cmd.OutOrStdout(), "%s/flowmap/#%s\n(valid until %s)\n", strings.TrimRight(base, "/"), frag,
				time.Unix(t.ExpiresUnix, 0).Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&class, "class", "", "class id")
	cmd.Flags().StringVar(&base, "url", "https://localhost:8443", "the relay's public https address")
	return cmd
}
