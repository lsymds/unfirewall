package unfirewall

import "net"

// SourceType represents the available source options.
type SourceType string

const (
	SourceCloudflare = SourceType("cloudflare")
)

// Action represents the available firewall options for a rule.
type Action string

const (
	ActionAllow = Action("allow")
	ActionDeny  = Action("deny")
)

// FirewallType represents the available firewall options.
type FirewallType string

const (
	FirewallUfw     = FirewallType("ufw")
	FirewallHetzner = FirewallType("hetzner")
)

// Rule contains the different configuration options required to create firewall rules.
type Rule struct {
	Action     Action
	Source     Source
	Port       uint16
	Ports      []uint16
	PortRange  [2]uint16
	Interfaces []string
}

// Firewall is an abstraction of an underlying Firewall. An example could be UFW or AWS' Security Groups.
type Firewall interface {
	AddRule(r *Rule) error
	Type() FirewallType
}

// Source is an abstraction
type Source interface {
	IPAddresses() ([]net.IP, error)
	Type() SourceType
}
