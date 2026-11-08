// Shared raw-sockaddr decoding. Every sockaddr this server reads (from
// getsockname/getpeername via std::net, from recvfrom's source address,
// and from getaddrinfo's candidate list) uses the same POSIX layout —
// a 2-byte family field, a 2-byte big-endian port, then the address
// bytes (offset 4 for IPv4, 8 for IPv6) — but came from three separate,
// independently-reimplemented copies of this logic (one in
// server_tcp.c3, two in server_udp.c3), flagged by two independent
// reviews. This is the one copy.
module socks5::server;

import std::net, std::net::os, std::core::mem;

<*
 Decodes a raw sockaddr byte buffer (AF_INET or AF_INET6 only — this
 server never handles anything else) into an address and its port.
 `out_port` may be null when the caller only wants the address.
 @return "false if `bytes` is too short or not a family this server supports"
*>
fn bool sockaddr_decode(char[] bytes, InetAddress* out_addr, ushort* out_port)
{
	if (bytes.len < 8) return false;

	$if env::DARWIN || env::BSD_FAMILY:
		AIFamily family = (AIFamily)bytes[1];
	$else
		AIFamily family = (AIFamily)*(ushort*)bytes.ptr;
	$endif

	ushort port = ((ushort)(char)bytes[2] << 8) | (ushort)(char)bytes[3];

	switch (family)
	{
		case os::AF_INET:
			*out_addr = { .ipv4 = { .a = bytes[4], .b = bytes[5], .c = bytes[6], .d = bytes[7] } };
			if (out_port) *out_port = port;
			return true;

		case os::AF_INET6:
			if (bytes.len < 24) return false;
			InetAddress addr = { .is_ipv6 = true };
			mem::copy(&addr.ipv6, &bytes[8], 16);
			*out_addr = addr;
			if (out_port) *out_port = port;
			return true;

		default:
			return false;
	}
}
