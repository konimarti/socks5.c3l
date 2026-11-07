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

fn void test_configure_allow_private_disables_check()
{
	configure(true);
	assert(!is_denied(net::ipv4_from_str("127.0.0.1")!!));
	assert(!is_denied(net::ipv6_from_str("::1")!!));
	configure(false); // restore default for any other test running in this process
	assert(is_denied(net::ipv4_from_str("127.0.0.1")!!));
}
