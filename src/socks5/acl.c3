// Destination ACL: by default, denies requests to loopback/private/
// link-local address ranges — the classic open-proxy-to-internal-network
// abuse vector ("SSRF via proxy": a client asks the proxy to connect
// somewhere the proxy's own network can reach but the client couldn't).
// RFC 1928 section 6 defines Socks5ReplyCode.NOT_ALLOWED (0x02) for exactly
// this case. A single process-wide policy (configure()), not a per-
// Socks5Server setting — this CLI only ever runs one Socks5Server per process, and
// threading a policy parameter through every command handler signature
// for a single-tenant process isn't worth the churn.
module socks5::acl;

import std::net, std::core::mem;

struct Socks5CidrV4
{
	char[4] net;
	char prefix;
}

struct Socks5CidrV6
{
	char[16] net;
	char prefix;
}

const Socks5CidrV4[6] DEFAULT_DENIED_V4 = {
	{ { 0, 0, 0, 0 }, 8 },      // 0.0.0.0/8, "this network"
	{ { 10, 0, 0, 0 }, 8 },     // RFC 1918 private
	{ { 127, 0, 0, 0 }, 8 },    // loopback
	{ { 169, 254, 0, 0 }, 16 }, // link-local
	{ { 172, 16, 0, 0 }, 12 },  // RFC 1918 private
	{ { 192, 168, 0, 0 }, 16 }, // RFC 1918 private
};

const Socks5CidrV6[4] DEFAULT_DENIED_V6 = {
	{ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 128 },     // :: unspecified (routes to loopback)
	{ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 128 },     // ::1 loopback
	{ { 0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 7 },    // fc00::/7 unique local
	{ { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 10 }, // fe80::/10 link-local
};

bool g_allow_private = false;

<*
 Call once at startup. allow_private = true disables the whole check
 (is_denied always returns false) — for deployments that intentionally
 proxy into their own private network.
*>
fn void configure(bool allow_private)
{
	g_allow_private = allow_private;
}

fn bool matches_v4(char[4] addr, Socks5CidrV4 c)
{
	// `32 - prefix` must never reach 32: shifting a 32-bit value by 32
	// is out-of-range and panics (verified empirically) rather than
	// producing the all-zero mask a /0 match needs.
	if (c.prefix == 0) return true;
	uint mask = c.prefix >= 32 ? uint::max : ~(uint)0 << (32 - c.prefix);
	uint a = ((uint)addr[0] << 24) | ((uint)addr[1] << 16) | ((uint)addr[2] << 8) | (uint)addr[3];
	uint n = ((uint)c.net[0] << 24) | ((uint)c.net[1] << 16) | ((uint)c.net[2] << 8) | (uint)c.net[3];
	return (a & mask) == (n & mask);
}

fn bool matches_v6(char[16] addr, Socks5CidrV6 c)
{
	char full_bytes = c.prefix / 8;
	char rem_bits = c.prefix % 8;
	for (char i = 0; i < full_bytes; i++)
	{
		if (addr[i] != c.net[i]) return false;
	}
	if (rem_bits > 0)
	{
		char mask = (char)(0xff << (8 - rem_bits));
		if ((addr[full_bytes] & mask) != (c.net[full_bytes] & mask)) return false;
	}
	return true;
}

const char[12] IPV4_MAPPED_PREFIX = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

<*
 True if `addr` is in the default-denied set and the policy hasn't
 disabled the check (configure(true)).
*>
fn bool is_denied(InetAddress addr)
{
	if (g_allow_private) return false;
	if (addr.is_ipv6)
	{
		char[16] raw;
		mem::copy(&raw, &addr.ipv6, 16);

		// RFC 4291 section 2.5.5.2: ::ffff:a.b.c.d is an IPv4-mapped
		// IPv6 address — a dual-stack kernel routes it exactly like
		// the embedded IPv4 address, so it must be checked against
		// the IPv4 list, not just the (disjoint) IPv6 one. Without
		// this, ::ffff:127.0.0.1 reaches loopback despite 127.0.0.0/8
		// being denied — confirmed by two independent reviews against
		// the real running server.
		bool is_v4_mapped = true;
		for (usz i = 0; i < 12; i++)
		{
			if (raw[i] != IPV4_MAPPED_PREFIX[i]) { is_v4_mapped = false; break; }
		}
		if (is_v4_mapped)
		{
			char[4] embedded_v4 = { raw[12], raw[13], raw[14], raw[15] };
			foreach (Socks5CidrV4 c : DEFAULT_DENIED_V4) if (matches_v4(embedded_v4, c)) return true;
			return false;
		}

		foreach (Socks5CidrV6 c : DEFAULT_DENIED_V6) if (matches_v6(raw, c)) return true;
		return false;
	}
	char[4] raw = { addr.ipv4.a, addr.ipv4.b, addr.ipv4.c, addr.ipv4.d };
	foreach (Socks5CidrV4 c : DEFAULT_DENIED_V4) if (matches_v4(raw, c)) return true;
	return false;
}
