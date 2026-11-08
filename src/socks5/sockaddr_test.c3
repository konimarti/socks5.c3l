module socks5::sockaddr @test;

import std::net;
import socks5::proto;

fn void test_encode_decode_round_trip_ipv4()
{
	InetAddress addr = { .ipv4 = { .a = 192, .b = 168, .c = 1, .d = 42 } };
	char[16] sa;
	Socklen_t sa_len = 0;
	assert(sockaddr_encode(addr, 8080, sa[0..], &sa_len), "encode ipv4");
	assert(sa_len == 16, "ipv4 sockaddr is 16 bytes");

	InetAddress decoded;
	ushort port;
	assert(sockaddr_decode(sa[0..sa_len - 1], &decoded, &port), "decode ipv4");
	assert(!decoded.is_ipv6, "decoded family is ipv4");
	assert(decoded.ipv4.a == 192 && decoded.ipv4.b == 168 && decoded.ipv4.c == 1 && decoded.ipv4.d == 42, "decoded ipv4 bytes match");
	assert(port == 8080, "decoded port matches");
}

fn void test_encode_decode_round_trip_ipv6()
{
	InetAddress addr = { .is_ipv6 = true };
	addr.ipv6.a = 0;
	addr.ipv6.b = 0;
	addr.ipv6.c = 0;
	addr.ipv6.d = 0;
	addr.ipv6.e = 0;
	addr.ipv6.f = 0;
	addr.ipv6.g = 0;
	addr.ipv6.h = 1; // ::1
	char[28] sa;
	Socklen_t sa_len = 0;
	assert(sockaddr_encode(addr, 443, sa[0..], &sa_len), "encode ipv6");
	assert(sa_len == 28, "ipv6 sockaddr is 28 bytes");

	InetAddress decoded;
	ushort port;
	assert(sockaddr_decode(sa[0..sa_len - 1], &decoded, &port), "decode ipv6");
	assert(decoded.is_ipv6, "decoded family is ipv6");
	assert(decoded.ipv6.h == 1, "decoded ipv6 bytes match");
	assert(port == 443, "decoded port matches");
}

fn void test_encode_ipv4_buffer_too_small()
{
	InetAddress addr = { .ipv4 = { .a = 1, .b = 2, .c = 3, .d = 4 } };
	char[15] sa;
	Socklen_t sa_len = 0;
	assert(!sockaddr_encode(addr, 1, sa[0..], &sa_len), "15 bytes is one short of the 16 ipv4 needs");
}

fn void test_encode_ipv6_buffer_too_small()
{
	InetAddress addr = { .is_ipv6 = true };
	char[27] sa;
	Socklen_t sa_len = 0;
	assert(!sockaddr_encode(addr, 1, sa[0..], &sa_len), "27 bytes is one short of the 28 ipv6 needs");
}

fn void test_address_to_sockaddr_ipv4_matches_direct_encode()
{
	proto::Address addr = { .atype = IPV4, .ipv4 = { 10, 0, 0, 1 }, .port = 53 };
	char[16] via_address;
	Socklen_t via_address_len = 0;
	assert(address_to_sockaddr(addr, via_address[0..], &via_address_len), "address_to_sockaddr ipv4");

	InetAddress ip = { .ipv4 = { .a = 10, .b = 0, .c = 0, .d = 1 } };
	char[16] via_encode;
	Socklen_t via_encode_len = 0;
	assert(sockaddr_encode(ip, 53, via_encode[0..], &via_encode_len), "sockaddr_encode ipv4");

	assert(via_address_len == via_encode_len, "same length");
	assert(mem::equals(&via_address, &via_encode, (usz)via_address_len), "same bytes");
}

fn void test_address_to_sockaddr_domain_not_supported()
{
	// DOMAIN needs DNS resolution, not formatting - that's a server-side
	// concern (socks5::server's resolve_destination), not this module's.
	proto::Address addr = { .atype = DOMAIN, .domain = "example.com", .port = 80 };
	char[128] sa;
	Socklen_t sa_len = 0;
	assert(!address_to_sockaddr(addr, sa[0..], &sa_len), "DOMAIN is out of scope for address_to_sockaddr");
}
