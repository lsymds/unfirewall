package cloudflare

import (
	"net"

	"github.com/lsymds/unfirewall/internal/unfirewall"
)

// CloudflareSource is an implementation of the [unfirewall.Source] interface that sources relevant Cloudflare
// IP addresses to whitelist.
type CloudflareSource struct{}

// Type returns the underlying [unfirewall.SourceType] represented by this struct.
func (c CloudflareSource) Type() unfirewall.SourceType {
	return unfirewall.SourceCloudflare
}

// IPAddresses retrieves Cloudflare's IP addresses that should be whitelisted in the firewall according to the
// requested configuration.
func (c CloudflareSource) IPAddresses() ([]net.IP, error) {
	return nil, nil
}

// New creates a [CloudflareSource] instance that is configured according to the passed parameters.
func New() (CloudflareSource, error) {
	return CloudflareSource{}, nil
}
