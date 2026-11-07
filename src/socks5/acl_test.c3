module socks5::acl;

import std::net;

<*
 RFC 4291 2.5.5.2: ::ffff:a.b.c.d is an IPv4-mapped IPv6 address — a
 dual-stack kernel routes it exactly like the embedded IPv4 address.
 Confirmed by two independent reviews (reviews/sprint2-review-v1.md,
 sprint2-review-v2.md) that this bypassed the ACL entirely before the
 fix, including against the real running server.
*>
fn InetAddress ipv4_mapped(char a, char b, char c, char d)
{
	InetAddress addr = { .is_ipv6 = true };
	addr.ipv6.a = 0;
	addr.ipv6.b = 0;
	addr.ipv6.c = 0;
	addr.ipv6.d = 0;
	addr.ipv6.e = 0;
	addr.ipv6.f = 0xffff;
	addr.ipv6.g = ((ushort)a << 8) | (ushort)b;
	addr.ipv6.h = ((ushort)c << 8) | (ushort)d;
	return addr;
}

module socks5::acl @test;

import std::net;

fn void test_default_denies_loopback_private_link_local_v4()
{
	assert(is_denied(net::ipv4_from_str("127.0.0.1")!!));
	assert(is_denied(net::ipv4_from_str("10.1.2.3")!!));
	assert(is_denied(net::ipv4_from_str("172.16.0.1")!!));
	assert(is_denied(net::ipv4_from_str("172.31.255.255")!!));
	assert(is_denied(net::ipv4_from_str("192.168.1.1")!!));
	assert(is_denied(net::ipv4_from_str("169.254.1.1")!!));
}

fn void test_default_allows_public_v4()
{
	assert(!is_denied(net::ipv4_from_str("8.8.8.8")!!));
	assert(!is_denied(net::ipv4_from_str("172.15.255.255")!!)); // just below 172.16.0.0/12
	assert(!is_denied(net::ipv4_from_str("172.32.0.0")!!));     // just above 172.16.0.0/12
	assert(!is_denied(net::ipv4_from_str("93.184.216.34")!!));  // example.com-ish public IP
}

fn void test_default_denies_loopback_private_link_local_v6()
{
	assert(is_denied(net::ipv6_from_str("::1")!!));
	assert(is_denied(net::ipv6_from_str("fc00::1")!!));
	assert(is_denied(net::ipv6_from_str("fdff:ffff::1")!!));
	assert(is_denied(net::ipv6_from_str("fe80::1")!!));
}

fn void test_default_allows_public_v6()
{
	assert(!is_denied(net::ipv6_from_str("2001:4860:4860::8888")!!)); // Google public DNS
}

fn void test_ipv4_mapped_ipv6_denied_when_embedded_v4_is_denied()
{
	assert(is_denied(ipv4_mapped(127, 0, 0, 1)));
	assert(is_denied(ipv4_mapped(10, 1, 2, 3)));
	assert(is_denied(ipv4_mapped(192, 168, 1, 1)));
}

fn void test_ipv4_mapped_ipv6_allowed_when_embedded_v4_is_public()
{
	assert(!is_denied(ipv4_mapped(8, 8, 8, 8)));
}

fn void test_unspecified_v6_denied()
{
	assert(is_denied(net::ipv6_from_str("::")!!));
}

fn void test_v4_prefix_zero_matches_everything_without_panicking()
{
	CidrV4 match_all = { { 0, 0, 0, 0 }, 0 };
	assert(matches_v4({ 1, 2, 3, 4 }, match_all));
	assert(matches_v4({ 255, 255, 255, 255 }, match_all));
}

fn void test_configure_allow_private_disables_check()
{
	configure(true);
	assert(!is_denied(net::ipv4_from_str("127.0.0.1")!!));
	assert(!is_denied(net::ipv6_from_str("::1")!!));
	configure(false); // restore default for any other test running in this process
	assert(is_denied(net::ipv4_from_str("127.0.0.1")!!));
}
