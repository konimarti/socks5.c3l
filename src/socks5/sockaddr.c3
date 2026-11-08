// Shared raw-sockaddr conversion. Every sockaddr this library reads or
// builds (from getsockname/getpeername via std::net, from recvfrom's
// source address, from getaddrinfo's candidate list, and from encoding a
// proto::Address for sendto/connect/bind) uses the same POSIX layout — a
// 2-byte family field, a 2-byte big-endian port, then the address bytes
// (offset 4 for IPv4, 8 for IPv6) — but came from independently
// reimplemented copies of this logic in server_tcp.c3 and server_udp.c3,
// flagged by two independent reviews. This is the one copy. std::net has
// no public equivalent (its own sockaddr handling is @private), and both
// the server (binding/relaying) and the client (formatting a BIND/UDP
// ASSOCIATE reply's address for the caller) need it, so it lives in its
// own module rather than under socks5::server or socks5::client.
module socks5::sockaddr;

import std::net, std::net::os, std::core::mem;
import socks5::proto;

<*
 Decodes a raw sockaddr byte buffer (AF_INET or AF_INET6 only — this
 library never handles anything else) into an address and its port.
 `out_port` may be null when the caller only wants the address.
 @return "false if `bytes` is too short or not a family this library supports"
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

<*
 Encodes an address and port into a raw sockaddr byte buffer (AF_INET or
 AF_INET6, chosen from `addr.is_ipv6`). `out_sa` must be at least 16
 bytes for IPv4 or 28 for IPv6.
 @return "false if `out_sa` is too small"
*>
fn bool sockaddr_encode(InetAddress addr, ushort port, char[] out_sa, Socklen_t* out_len)
{
	usz needed = addr.is_ipv6 ? 28 : 16;
	if (out_sa.len < needed) return false;
	mem::set(out_sa.ptr, 0, (sz)needed);

	if (addr.is_ipv6)
	{
		$if env::DARWIN || env::BSD_FAMILY:
			out_sa[0] = 28;
			out_sa[1] = (char)os::AF_INET6;
		$else
			*(ushort*)out_sa.ptr = (ushort)os::AF_INET6;
		$endif
		out_sa[2] = (char)(port >> 8);
		out_sa[3] = (char)(port & 0xff);
		mem::copy(&out_sa[8], &addr.ipv6, 16);
	}
	else
	{
		$if env::DARWIN || env::BSD_FAMILY:
			out_sa[0] = 16;
			out_sa[1] = (char)os::AF_INET;
		$else
			*(ushort*)out_sa.ptr = (ushort)os::AF_INET;
		$endif
		out_sa[2] = (char)(port >> 8);
		out_sa[3] = (char)(port & 0xff);
		out_sa[4] = addr.ipv4.a;
		out_sa[5] = addr.ipv4.b;
		out_sa[6] = addr.ipv4.c;
		out_sa[7] = addr.ipv4.d;
	}
	*out_len = (Socklen_t)needed;
	return true;
}

<*
 Encodes a proto::Address (as decoded from a SOCKS5 reply's BND.ADDR, or
 built for a request's DST.ADDR) into a raw sockaddr byte buffer, for
 handing straight to sendto/connect/bind. DOMAIN addresses need DNS
 resolution, not formatting, so they are out of scope here and this
 returns false for them — RFC 1928 replies carry IPv4/IPv6 in practice.
 @return "false for AddressType.DOMAIN, or if `out_sa` is too small"
*>
fn bool address_to_sockaddr(proto::Address addr, char[] out_sa, Socklen_t* out_len)
{
	switch (addr.atype)
	{
		case IPV4:
			InetAddress ip = { .ipv4 = { .a = addr.ipv4[0], .b = addr.ipv4[1], .c = addr.ipv4[2], .d = addr.ipv4[3] } };
			return sockaddr_encode(ip, addr.port, out_sa, out_len);

		case IPV6:
			InetAddress ip = { .is_ipv6 = true };
			mem::copy(&ip.ipv6, &addr.ipv6, 16);
			return sockaddr_encode(ip, addr.port, out_sa, out_len);

		default:
			return false;
	}
}
