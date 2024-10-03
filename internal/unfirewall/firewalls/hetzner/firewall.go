package hetzner

import "github.com/lsymds/unfirewall/internal/unfirewall"

// HetznerFirewall is a [unfirewall.Firewall] implementation that interacts with Hetzner Cloud's network firewall.
type HetznerFirewall struct{}

// AddRule creates a rule within the current Hetzner Cloud network firewall.
func (h HetznerFirewall) AddRule(r *unfirewall.Rule) error {
	return nil
}

// Type returns the underlying [unfirewall.FirewallType] represented by this struct.
func (h HetznerFirewall) Type() unfirewall.FirewallType {
	return unfirewall.FirewallHetzner
}

// New creates an instance of [HetznerFirewall] that points to the network firewall id specified under the account
// represented by the access token.
func New() (HetznerFirewall, error) {
	return HetznerFirewall{}, nil
}
