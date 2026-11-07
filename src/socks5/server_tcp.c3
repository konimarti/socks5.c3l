// CONNECT and BIND command handlers (RFC 1928 section 4, 6).
//
// SPEC for handle_connect(conn, dst):
//   - dst is the already-decoded, already-validated target address/port
//     from the client's request (proto::decode_request already ran).
//   - Dial dst with tcp::connect (resolve the address per dst.atype:
//     IPV4/IPV6 use dst.ipv4/dst.ipv6 directly; DOMAIN uses dst.domain,
//     letting the stdlib resolver handle DNS).
//   - On dial failure, map the error to the closest proto::ReplyCode
//     (HOST_UNREACHABLE / CONNECTION_REFUSED / NETWORK_UNREACHABLE /
//     GENERAL_FAILURE) and proto::encode_reply it back to conn, then
//     return without relaying.
//   - On success, proto::encode_reply(conn, SUCCEEDED, <bound local
//     address of the new outbound socket>) and then
//     socks5::relay::relay_bidirectional(conn, &target) until either
//     side closes. Close the target socket before returning (conn is
//     closed by the caller).
//
// SPEC for handle_bind(conn, dst):
//   - Open a new TCP listening socket (ephemeral port; dst is advisory
//     per RFC 1928 and may be ignored for the bind address — bind to
//     the same interface conn arrived on, or 0.0.0.0, either is a
//     reasonable v1 choice as long as it's documented).
//   - First reply: proto::encode_reply(conn, SUCCEEDED, <listener's
//     bound address/port>).
//   - Accept exactly one incoming connection on that listener (RFC 1928
//     does not support multiple incoming connections per BIND), with a
//     bounded wait — do not block forever; pick a timeout and encode
//     GENERAL_FAILURE (or a more specific code) if it expires.
//   - Second reply: proto::encode_reply(conn, SUCCEEDED, <peer address
//     of the accepted connection>).
//   - Then socks5::relay::relay_bidirectional(conn, &accepted) exactly
//     like CONNECT. Close the listener once the one connection is
//     accepted (or once the wait times out).
//
// Reuse socks5::relay::relay_bidirectional for the data phase of both
// commands — do not write a second copy loop.
module socks5::server;

import std::net, std::net::tcp, std::net::os, std::time;
import socks5::proto, socks5::relay, socks5::acl;

const Duration BIND_TIMEOUT = (Duration)(30L * time::SEC);

<*
 Maps a dial fault from tcp::connect to the closest SOCKS5 ReplyCode.
*>
fn proto::ReplyCode map_connect_error(fault err)
{
	switch (err)
	{
		case net::CONNECTION_REFUSED:
			return CONNECTION_REFUSED;
		case net::NETWORK_UNREACHABLE:
			return NETWORK_UNREACHABLE;
		case net::CONNECTION_TIMED_OUT:
			return HOST_UNREACHABLE;
		case net::ADDRINFO_FAILED:
			return HOST_UNREACHABLE;
		default:
			return GENERAL_FAILURE;
	}
}

<*
 Formats dst as a host string suitable for tcp::connect into out_buf.
 IPV4: dotted-decimal
 DOMAIN: direct domain string
 IPV6: hex groups
*>
fn String? dst_to_host(proto::Address dst, char[] out_buf)
{
	switch (dst.atype)
	{
		case IPV4:
			return string::bformat(out_buf, "%d.%d.%d.%d",
				(uint)dst.ipv4[0],
				(uint)dst.ipv4[1],
				(uint)dst.ipv4[2],
				(uint)dst.ipv4[3]);
		case DOMAIN:
			return dst.domain;
		case IPV6:
			ushort[8] g;
			for (usz i = 0; i < 8; i++)
			{
				g[i] = ((ushort)dst.ipv6[i * 2] << 8) | (ushort)dst.ipv6[i * 2 + 1];
			}
			return string::bformat(out_buf, "%x:%x:%x:%x:%x:%x:%x:%x",
				g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7]);
		default:
			return proto::UNSUPPORTED_ADDRESS_TYPE~;
	}
}

<*
 Extracts the local bound address of a socket as a proto::Address.
*>
fn proto::Address socket_local_address(Socket* s)
{
	proto::Address out = { .atype = IPV4 };
	if (try port = s.local_port()) out.port = port;

	if (try laddr = s.local_address())
	{
		if (laddr.is_ipv6)
		{
			out.atype = IPV6;
			mem::copy(&out.ipv6, &laddr.ipv6, 16);
		}
		else
		{
			out.atype = IPV4;
			out.ipv4 = { laddr.ipv4.a, laddr.ipv4.b, laddr.ipv4.c, laddr.ipv4.d };
		}
	}
	return out;
}

<*
 Extracts the peer connected address of a socket as a proto::Address.
*>
fn proto::Address socket_peer_address(Socket* s)
{
	proto::Address out = { .atype = IPV4 };
	if (try port = s.peer_port()) out.port = port;

	if (try paddr = s.peer_address())
	{
		if (paddr.is_ipv6)
		{
			out.atype = IPV6;
			mem::copy(&out.ipv6, &paddr.ipv6, 16);
		}
		else
		{
			out.atype = IPV4;
			out.ipv4 = { paddr.ipv4.a, paddr.ipv4.b, paddr.ipv4.c, paddr.ipv4.d };
		}
	}
	return out;
}

fn bool sockaddr_to_inet(SockAddrPtr sa, Socklen_t sa_len, InetAddress* out_addr)
{
	if (sa_len < 8 || !sa) return false;
	char[] bytes = ((char*)sa)[:sa_len];

	$if env::DARWIN || env::BSD_FAMILY:
		AIFamily family = (AIFamily)bytes[1];
	$else
		AIFamily family = (AIFamily)*(ushort*)bytes.ptr;
	$endif

	switch (family)
	{
		case os::AF_INET:
			*out_addr = {
				.ipv4 = { .a = bytes[4], .b = bytes[5], .c = bytes[6], .d = bytes[7] }
			};
			return true;

		case os::AF_INET6:
			if (sa_len < 24) return false;
			InetAddress addr = { .is_ipv6 = true };
			mem::copy(&addr.ipv6, &bytes[8], 16);
			*out_addr = addr;
			return true;

		default:
			return false;
	}
}

fn void handle_connect(TcpSocket* conn, proto::Address dst)
{
	proto::Address empty_addr = { .atype = IPV4 };

	// Case 1: IPV4 or IPV6 literal destination — check ACL before dialing.
	if (dst.atype == IPV4 || dst.atype == IPV6)
	{
		InetAddress ip;
		if (dst.atype == IPV6)
		{
			ip = { .is_ipv6 = true };
			mem::copy(&ip.ipv6, &dst.ipv6, 16);
		}
		else
		{
			ip = { .ipv4 = { .a = dst.ipv4[0], .b = dst.ipv4[1], .c = dst.ipv4[2], .d = dst.ipv4[3] } };
		}

		if (acl::is_denied(ip))
		{
			(void)proto::encode_reply(conn, NOT_ALLOWED, empty_addr);
			return;
		}

		char[64] host_buf;
		String? host = dst_to_host(dst, &host_buf);
		if (catch host)
		{
			(void)proto::encode_reply(conn, ADDRESS_TYPE_NOT_SUPPORTED, empty_addr);
			return;
		}

		TcpSocket? target = tcp::connect(host, (int)dst.port);
		if (catch err = target)
		{
			proto::ReplyCode code = map_connect_error(err);
			(void)proto::encode_reply(conn, code, empty_addr);
			return;
		}
		defer (void)target.close();

		proto::Address bnd = socket_local_address((Socket*)&target);
		if (catch proto::encode_reply(conn, SUCCEEDED, bnd)) return;

		relay::relay_bidirectional((Socket*)conn, (Socket*)&target);
		return;
	}

	// Case 2: DOMAIN destination — resolve first, check each candidate address against ACL.
	if (dst.atype == DOMAIN)
	{
		AddrInfo*? ai = net::addrinfo(dst.domain, (int)dst.port, os::AF_UNSPEC, os::SOCK_STREAM);
		if (catch err = ai)
		{
			proto::ReplyCode code = map_connect_error(err);
			(void)proto::encode_reply(conn, code, empty_addr);
			return;
		}
		defer os::freeaddrinfo(ai);

		bool any_allowed = false;
		fault last_connect_err = net::CONNECT_FAILED;
		TcpSocket real_target = {};
		bool connected = false;

		for (AddrInfo* curr = ai; curr != null; curr = curr.ai_next)
		{
			InetAddress cand;
			if (!sockaddr_to_inet(curr.ai_addr, curr.ai_addrlen, &cand)) continue;
			if (acl::is_denied(cand)) continue;

			any_allowed = true;

			// Temporarily isolate curr from the chain so connect_to only dials this candidate
			AddrInfo* next = curr.ai_next;
			curr.ai_next = null;
			TcpSocket? res = tcp::connect_to(curr);
			curr.ai_next = next;

			if (catch err = res)
			{
				last_connect_err = err;
				continue;
			}

			real_target = res;
			connected = true;
			break;
		}

		if (!any_allowed)
		{
			// Every candidate was denied by ACL ruleset (e.g. evil.com -> 127.0.0.1)
			(void)proto::encode_reply(conn, NOT_ALLOWED, empty_addr);
			return;
		}

		if (!connected)
		{
			// Candidates were allowed, but dialing failed
			proto::ReplyCode code = map_connect_error(last_connect_err);
			(void)proto::encode_reply(conn, code, empty_addr);
			return;
		}
		defer (void)real_target.close();

		proto::Address bnd = socket_local_address((Socket*)&real_target);
		if (catch proto::encode_reply(conn, SUCCEEDED, bnd)) return;

		relay::relay_bidirectional((Socket*)conn, (Socket*)&real_target);
		return;
	}

	// Case 3: Unsupported address type
	(void)proto::encode_reply(conn, ADDRESS_TYPE_NOT_SUPPORTED, empty_addr);
}

fn void handle_bind(TcpSocket* conn, proto::Address dst)
{
	proto::Address empty_addr = { .atype = IPV4 };

	// Bind to the same interface conn arrived on, with a wildcard
	// fallback in the matching address family (an IPv6 connection must
	// not fall back to the IPv4 wildcard, which would bind the wrong
	// family and report an address the client can't reach).
	char[64] host_buf;
	String bind_host = "0.0.0.0";
	InetAddress? conn_local = conn.local_address();
	if (try cl = conn_local)
	{
		if (cl.is_ipv6)
		{
			bind_host = "::";
		}
		else
		{
			bind_host = string::bformat(&host_buf, "%d.%d.%d.%d",
				(uint)cl.ipv4.a, (uint)cl.ipv4.b, (uint)cl.ipv4.c, (uint)cl.ipv4.d);
		}
	}

	TcpServerSocket? listener = tcp::listen(bind_host, 0, 1, REUSEADDR);
	if (catch listener)
	{
		(void)proto::encode_reply(conn, GENERAL_FAILURE, empty_addr);
		return;
	}
	defer (void)listener.close();

	// First reply: listener's bound address and ephemeral port. A
	// wildcard bind reports the wildcard address back, not a reachable
	// one; substitute conn's local address in the matching family.
	proto::Address listener_bnd = socket_local_address((Socket*)&listener);
	if (try cl = conn_local)
	{
		if (listener_bnd.atype == IPV4 && listener_bnd.ipv4 == { 0, 0, 0, 0 } && !cl.is_ipv6)
		{
			listener_bnd.ipv4 = { cl.ipv4.a, cl.ipv4.b, cl.ipv4.c, cl.ipv4.d };
		}
		else if (listener_bnd.atype == IPV6 && cl.is_ipv6)
		{
			char[16] zero;
			if (listener_bnd.ipv6 == zero)
			{
				mem::copy(&listener_bnd.ipv6, &cl.ipv6, 16);
			}
		}
	}
	if (catch proto::encode_reply(conn, SUCCEEDED, listener_bnd)) return;

	// Accept exactly one connection with bounded wait.
	Poll[2] polls = {
		{ .socket = listener.sock, .events = ANY_READ },
		{ .socket = conn.sock, .events = ANY_READ },
	};
	ulong? n = net::poll(polls[0..], BIND_TIMEOUT);
	if (catch n) return;
	if (!n)
	{
		// Bounded wait expired: report failure to client.
		(void)proto::encode_reply(conn, GENERAL_FAILURE, empty_addr);
		return;
	}

	bool listener_ready = ((ushort)polls[0].revents & (ushort)PollSubscribe.ANY_READ) != 0;
	if (!listener_ready)
	{
		// Client connection had activity/closure before listener got a connection.
		char[1] peek_buf;
		if (try peek_n = conn.peek(&peek_buf))
		{
			if (peek_n == 0) return;
		}

		(void)proto::encode_reply(conn, GENERAL_FAILURE, empty_addr);
		return;
	}

	TcpSocket? accepted = tcp::accept(&listener);
	if (catch accepted)
	{
		(void)proto::encode_reply(conn, GENERAL_FAILURE, empty_addr);
		return;
	}
	defer (void)accepted.close();

	// Close listener once the connection is accepted.
	(void)listener.close();

	// Second reply: peer address of accepted connection.
	proto::Address peer_bnd = socket_peer_address((Socket*)&accepted);
	if (catch proto::encode_reply(conn, SUCCEEDED, peer_bnd)) return;

	relay::relay_bidirectional((Socket*)conn, (Socket*)&accepted);
}
