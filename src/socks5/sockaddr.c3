// Shared raw-sockaddr conversion. std::net already decodes a raw sockaddr
// into an InetAddress and port (decode_sockaddr/decode_port in
// socket.c3), used internally by Socket.local_address/local_port — just
// marked @private, so sockaddr_decode below is a thin public wrapper
// around those (imported with @public) rather than a second
// implementation. There's no std::net equivalent for the other
// direction: it never builds a sockaddr from a bare IP+port, only ever
// consumes ready-made ones from getaddrinfo, because every connect/bind
// path goes through hostname resolution. This library needs that
// direction too (formatting a BIND/UDP ASSOCIATE reply's address, which
// already carries a literal IP, for sendto/connect/bind), so
// sockaddr_encode is still hand-rolled. Both used to be duplicated
// across server_tcp.c3 and server_udp.c3 (flagged by two independent
// reviews); this is the one copy, shared by client and server, hence
// its own module rather than living under socks5::server or
// socks5::client.
module socks5::sockaddr;

import std::net @public;
import std::net::os, std::core::mem;
import socks5::proto;

<*
 Decodes a raw sockaddr byte buffer (AF_INET or AF_INET6 only — this
 library never handles anything else) into an address and its port.
 `out_port` may be null when the caller only wants the address.
 @return "false if `bytes` is too short or not a family this library supports"
*>
fn bool sockaddr_decode(char[] bytes, InetAddress* out_addr, ushort* out_port)
{
	InetAddress? addr = net::decode_sockaddr(bytes);
	if (catch addr) return false;
	*out_addr = addr;
	if (out_port)
	{
		ushort? port = net::decode_port(bytes);
		if (catch port) return false;
		*out_port = port;
	}
	return true;
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
 Encodes a proto::Socks5Address (as decoded from a SOCKS5 reply's BND.ADDR, or
 built for a request's DST.ADDR) into a raw sockaddr byte buffer, for
 handing straight to sendto/connect/bind. DOMAIN addresses need DNS
 resolution, not formatting, so they are out of scope here and this
 returns false for them — RFC 1928 replies carry IPv4/IPv6 in practice.
 @return "false for AddressType.DOMAIN, or if `out_sa` is too small"
*>
fn bool address_to_sockaddr(proto::Socks5Address addr, char[] out_sa, Socklen_t* out_len)
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
