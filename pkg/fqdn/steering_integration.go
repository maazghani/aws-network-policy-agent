//go:build linux && fqdn_integration

package fqdn

import "errors"

// NewFQDNSteeringIntegration uses the production host plumbing. Cleanup retains
// the scoped forwarding guard, as required for enrolled endpoints during outage.
func NewFQDNSteeringIntegration(family int, mark uint32, table, priority int) (func() error, error) {
	if (family != 4 && family != 6) || mark == 0 || mark&DNSReplyMark != 0 || table <= 255 || priority <= 0 {
		return nil, errors.New("invalid DNS host steering configuration")
	}
	steering, err := installDNSSteering(family, mark, table, priority)
	if err != nil {
		return nil, err
	}
	return steering.close, nil
}
