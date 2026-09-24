package ipgeolocation

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ipResolver decides which address a request is geolocated by.
//
// The default is the address Traefik sees on the connection, because
// forwarded headers are set by clients and can be forged: trusting them
// blindly lets a visitor change their apparent country, or hide a flagged IP,
// by sending one header. Turn trustForwardedHeader on only when this instance
// sits behind a proxy you operate and that overwrites the header.
type ipResolver struct {
	trustForwarded bool
	headerName     string
	depth          int
	trustedProxies []*net.IPNet
}

func (r ipResolver) clientIP(req *http.Request) net.IP {
	peer := peerIP(req)

	if !r.trustForwarded {
		return peer
	}

	values := forwardedValues(req, r.headerName)
	if len(values) == 0 {
		return peer
	}

	// Depth counts from the right, so depth 1 is the address the closest
	// proxy reported. This is the reliable choice behind a known number of
	// hops.
	if r.depth > 0 {
		idx := len(values) - r.depth
		if idx >= 0 && idx < len(values) {
			if ip := parseIP(values[idx]); ip != nil {
				return ip
			}
		}
		return peer
	}

	// With a list of trusted proxies, walk from the right and return the
	// first address that is not one of ours.
	if len(r.trustedProxies) > 0 {
		for i := len(values) - 1; i >= 0; i-- {
			ip := parseIP(values[i])
			if ip == nil {
				continue
			}
			if !ipInNets(ip, r.trustedProxies) {
				return ip
			}
		}
		return peer
	}

	// Otherwise take the leftmost entry, which is the original client as
	// reported by the chain.
	for _, value := range values {
		if ip := parseIP(value); ip != nil {
			return ip
		}
	}
	return peer
}

func forwardedValues(req *http.Request, headerName string) []string {
	raw := req.Header.Values(headerName)
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func peerIP(req *http.Request) net.IP {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	return parseIP(host)
}

// parseIP accepts a bare address, a bracketed IPv6 address, an address with a
// port, and an IPv6 address with a zone.
func parseIP(value string) net.IP {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.LastIndex(value, "]"); end > 0 {
			value = value[1:end]
		}
	}
	if idx := strings.Index(value, "%"); idx > 0 {
		value = value[:idx]
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return net.ParseIP(strings.TrimSpace(host))
	}
	return nil
}

// parseCIDRs accepts CIDR blocks and bare addresses.
func parseCIDRs(values []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "/") {
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("%q is not a valid IP address or CIDR block", value)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			value = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid CIDR block: %v", value, err)
		}
		out = append(out, network)
	}
	return out, nil
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, network := range nets {
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// isLocalIP reports whether an address is loopback, link local, unspecified,
// or in a private range. Such addresses are absent from every public
// geolocation database, so the middleware skips them by default instead of
// treating internal traffic as unknown.
func isLocalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	// Carrier grade NAT and the IPv6 unique local range.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xC0 == 64 {
			return true
		}
	} else if len(ip) == net.IPv6len && ip[0]&0xFE == 0xFC {
		return true
	}
	return false
}
