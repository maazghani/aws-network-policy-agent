package clihelper

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
	"github.com/spf13/cobra"
)

// NewFQDNCommand is shared by the IPv4 and IPv6 diagnostic binaries.
func NewFQDNCommand() *cobra.Command {
	var ifindex uint32
	var address string
	cmd := &cobra.Command{Use: "fqdn", Short: "Read opt-in local FQDN diagnostics", Args: cobra.NoArgs}
	cmd.Flags().Uint32Var(&ifindex, "ifindex", 0, "Host veth interface index")
	cmd.Flags().StringVar(&address, "ip", "", "Assigned pod address")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		path := "/"
		if ifindex != 0 || address != "" {
			ip, err := netip.ParseAddr(address)
			if err != nil || ifindex == 0 {
				return fmt.Errorf("both a valid --ifindex and --ip are required")
			}
			path = "/endpoint?" + url.Values{"ifindex": {strconv.FormatUint(uint64(ifindex), 10)}, "ip": {ip.String()}}.Encode()
		}
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", fqdn.DiagnosticsSocket)
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		request, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, "http://nodeagent"+path, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("local diagnostics unavailable (requires --fqdn-diagnostics): %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("FQDN diagnostics: %s", response.Status)
		}
		_, err = io.Copy(cmd.OutOrStdout(), io.LimitReader(response.Body, 8<<20))
		return err
	}
	return cmd
}
