// UDP ASSOCIATE command handler (RFC 1928 section 7).
//
// SPEC for handle_udp_associate(conn, client_hint):
//   - client_hint is the client's advertised source address/port for its
//     UDP traffic (often 0.0.0.0:0 — many clients don't know their own
//     NAT-mapped address yet; do not require it to be non-zero).
//   - Open a UDP socket bound to an ephemeral port on the same interface
//     conn arrived on. proto::encode_reply(conn, SUCCEEDED, <that UDP
//     socket's bound address/port>) — this is the address the client
//     must send its UDP datagrams to.
//   - The association's lifetime is the TCP control connection's
//     lifetime (RFC 1928: "the UDP ASSOCIATE request... persists... for
//     the duration of the TCP connection"): watch conn with net::poll
//     alongside the UDP socket in one loop; when conn reaches EOF/error,
//     tear down the UDP socket and return. Do not run a separate
//     thread that outlives conn — conn closing must be the only exit
//     condition besides an explicit idle timeout.
//   - Required hardening (this is the exact defect class that took three
//     review passes to fully stamp out in the https.c3l sibling project:
//     an added "watch a secondary condition, relay/skip in a loop"
//     primitive with no bound on it): the datagram relay loop MUST have
//     both (a) an idle timeout (no datagram and no conn activity for N
//     seconds -> tear down; reuse socks5::relay::IDLE_TIMEOUT's duration
//     for consistency) and (b) a per-iteration bound is not needed if
//     poll is used correctly (poll blocks, it doesn't spin), but the
//     loop must still have no path that reads an unbounded number of
//     bytes per datagram — UDP datagrams are naturally bounded (<64KiB)
//     so a single fixed-size receive buffer (e.g. 65507 bytes, the max
//     UDP payload) read with one recv call per datagram is correct and
//     sufficient; do not accumulate across datagrams.
//   - Per datagram received FROM the client on the new UDP socket:
//     proto::decode_udp_header(datagram, allocator) to get the real
//     destination, then forward datagram.payload to that destination
//     (a second UDP socket, or reuse one UDP socket with sendto-style
//     addressing — check what std::net::udp exposes). Reject (drop,
//     don't crash) a datagram whose source address doesn't match the
//     client's observed address once one datagram has established it
//     (prevents a third party from injecting traffic into the
//     association) — RFC 1928 section 7, the "silently discard" clause.
//   - Per datagram received FROM the target destined back to the
//     client: wrap it with proto::encode_udp_header and send to the
//     client's UDP endpoint (the source address observed on the first
//     client->proxy datagram, not client_hint, since client_hint is
//     frequently 0.0.0.0:0).
//   - Fragmentation (FRAG != 0) is explicitly out of scope (v1
//     limitation, documented in proto.c3's UNSUPPORTED_FRAGMENTATION):
//     drop such datagrams, do not attempt reassembly.
module socks5::server;

import std::net, std::net::tcp, std::net::os, std::io, std::time, libc;
import socks5::proto, socks5::relay;

extern fn sz recvfrom(NativeSocket socket, void* buffer, usz length, CInt flags, SockAddrPtr address, Socklen_t* address_len);
extern fn sz sendto(NativeSocket socket, void* buffer, usz length, CInt flags, SockAddrPtr address, Socklen_t address_len);

const usz RECV_BUF_SIZE = 65536;

fn bool poll_readable(Poll p) => ((ushort)p.revents & (ushort)PollSubscribe.ANY_READ) != 0;
fn bool poll_has_error(Poll p) => ((ushort)p.revents & (ushort)(PollEvent.DISCONNECT | PollEvent.ERROR | PollEvent.INVALID)) != 0;

fn bool address_equals(proto::Address a, proto::Address b)
{
	if (a.atype != b.atype || a.port != b.port) return false;
	switch (a.atype)
	{
		case IPV4:
			return libc::memcmp(&a.ipv4, &b.ipv4, 4) == 0;
		case IPV6:
			return libc::memcmp(&a.ipv6, &b.ipv6, 16) == 0;
		case DOMAIN:
			return a.domain == b.domain;
	}
}

fn bool decode_sockaddr_to_proto(char[] storage, proto::Address* out_addr)
{
	if (storage.len < 8) return false;

	$if env::DARWIN || env::BSD_FAMILY:
		AIFamily family = (AIFamily)storage[1];
	$else
		AIFamily family = (AIFamily)*(ushort*)storage.ptr;
	$endif

	switch (family)
	{
		case os::AF_INET:
			out_addr.atype = IPV4;
			out_addr.port = (ushort)(((ushort)(char)storage[2] << 8) | (ushort)(char)storage[3]);
			mem::copy(&out_addr.ipv4, &storage[4], 4);
			return true;

		case os::AF_INET6:
			if (storage.len < 28) return false;
			out_addr.atype = IPV6;
			out_addr.port = (ushort)(((ushort)(char)storage[2] << 8) | (ushort)(char)storage[3]);
			mem::copy(&out_addr.ipv6, &storage[8], 16);
			return true;

		default:
			return false;
	}
}

fn bool address_to_sockaddr(proto::Address addr, char[] out_sa, Socklen_t* out_len)
{
	switch (addr.atype)
	{
		case IPV4:
			if (out_sa.len < 16) return false;
			mem::set(out_sa.ptr, 0, 16);
			$if env::DARWIN || env::BSD_FAMILY:
				out_sa[0] = 16;
				out_sa[1] = (char)os::AF_INET;
			$else
				*(ushort*)out_sa.ptr = (ushort)os::AF_INET;
			$endif
			out_sa[2] = (char)(addr.port >> 8);
			out_sa[3] = (char)(addr.port & 0xff);
			mem::copy(&out_sa[4], &addr.ipv4, 4);
			*out_len = 16;
			return true;

		case IPV6:
			if (out_sa.len < 28) return false;
			mem::set(out_sa.ptr, 0, 28);
			$if env::DARWIN || env::BSD_FAMILY:
				out_sa[0] = 28;
				out_sa[1] = (char)os::AF_INET6;
			$else
				*(ushort*)out_sa.ptr = (ushort)os::AF_INET6;
			$endif
			out_sa[2] = (char)(addr.port >> 8);
			out_sa[3] = (char)(addr.port & 0xff);
			mem::copy(&out_sa[8], &addr.ipv6, 16);
			*out_len = 28;
			return true;

		case DOMAIN:
			AddrInfo*? ai = net::addrinfo(addr.domain, (int)addr.port, os::AF_UNSPEC, os::SOCK_DGRAM);
			if (catch ai) return false;
			defer os::freeaddrinfo(ai);
			if ((usz)ai.ai_addrlen > out_sa.len) return false;
			*out_len = ai.ai_addrlen;
			mem::copy(out_sa.ptr, (void*)ai.ai_addr, (sz)ai.ai_addrlen);
			return true;
	}
}

fn Socket? bind_udp_local(InetAddress addr)
{
	char[128] sa;
	Socklen_t sa_len = 0;
	AIFamily family;

	if (addr.is_ipv6)
	{
		family = os::AF_INET6;
		sa_len = 28;
		mem::set(&sa, 0, 28);
		$if env::DARWIN || env::BSD_FAMILY:
			sa[0] = 28;
			sa[1] = (char)os::AF_INET6;
		$else
			*(ushort*)&sa = (ushort)os::AF_INET6;
		$endif
		mem::copy(&sa[8], &addr.ipv6, 16);
	}
	else
	{
		family = os::AF_INET;
		sa_len = 16;
		mem::set(&sa, 0, 16);
		$if env::DARWIN || env::BSD_FAMILY:
			sa[0] = 16;
			sa[1] = (char)os::AF_INET;
		$else
			*(ushort*)&sa = (ushort)os::AF_INET;
		$endif
		sa[4] = addr.ipv4.a;
		sa[5] = addr.ipv4.b;
		sa[6] = addr.ipv4.c;
		sa[7] = addr.ipv4.d;
	}

	NativeSocket fd = os::socket(family, os::SOCK_DGRAM, (AIProtocol)0);
	if (!fd.is_valid()) return net::GENERAL_ERROR~;

	if (os::bind(fd, (SockAddrPtr)&sa, sa_len) != 0)
	{
		(void)fd.close();
		return net::GENERAL_ERROR~;
	}

	Socket sock = { .sock = fd, .addrlen = sa_len };
	mem::copy(&sock.addr_storage, &sa, (sz)sa_len);
	return sock;
}

fn Socket? bind_udp_socket(String host, int port, AIFamily family)
{
	AddrInfo* ai = net::addrinfo(host, port, family, os::SOCK_DGRAM)!;
	defer os::freeaddrinfo(ai);

	NativeSocket fd = os::socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
	if (!fd.is_valid()) return net::GENERAL_ERROR~;

	if (os::bind(fd, ai.ai_addr, ai.ai_addrlen) != 0)
	{
		(void)fd.close();
		return net::GENERAL_ERROR~;
	}

	Socket sock = { .sock = fd, .addrlen = ai.ai_addrlen };
	mem::copy(&sock.addr_storage, (void*)ai.ai_addr, (sz)ai.ai_addrlen);
	return sock;
}

fn void handle_udp_associate(TcpSocket* conn, proto::Address client_hint)
{
	Address fallback;
	InetAddress? local_addr = conn.local_address();
	if (catch local_addr)
	{
		(void)proto::encode_reply(conn, GENERAL_FAILURE, fallback);
		return;
	}

	Socket? client_sock = bind_udp_local(local_addr);
	if (catch client_sock)
	{
		(void)proto::encode_reply(conn, GENERAL_FAILURE, fallback);
		return;
	}
	defer (void)client_sock.close();

	ushort? bound_port = client_sock.local_port();
	if (catch bound_port)
	{
		(void)proto::encode_reply(conn, GENERAL_FAILURE, fallback);
		return;
	}

	Address bnd_addr;
	if (local_addr.is_ipv6)
	{
		bnd_addr.atype = IPV6;
		mem::copy(&bnd_addr.ipv6, &local_addr.ipv6, 16);
	}
	else
	{
		bnd_addr.atype = IPV4;
		bnd_addr.ipv4 = { local_addr.ipv4.a, local_addr.ipv4.b, local_addr.ipv4.c, local_addr.ipv4.d };
	}
	bnd_addr.port = bound_port;

	if (catch proto::encode_reply(conn, SUCCEEDED, bnd_addr)) return;

	InetAddress any_addr;
	if (local_addr.is_ipv6)
	{
		any_addr.is_ipv6 = true;
	}
	Socket? target_sock = bind_udp_local(any_addr);
	if (catch target_sock) return;
	defer (void)target_sock.close();

	(void)client_sock.sock.set_non_blocking(true);
	(void)target_sock.sock.set_non_blocking(true);
	(void)conn.sock.set_non_blocking(true);

	bool client_pinned = false;
	proto::Address client_addr;
	char[128] client_sa;
	Socklen_t client_sa_len = 0;

	char[RECV_BUF_SIZE] recv_buf;

	Poll[3] polls = {
		{ .socket = conn.sock,        .events = ANY_READ },
		{ .socket = client_sock.sock, .events = ANY_READ },
		{ .socket = target_sock.sock, .events = ANY_READ },
	};

	while (true)
	{
		@pool()
		{
			ulong? n = net::poll(polls[0..], relay::IDLE_TIMEOUT);
			if (catch n) return;
			if (!n) return; // idle timeout: no activity for 300s

			// Check TCP control connection: EOF, disconnect, or error means association is over.
			if (poll_has_error(polls[0])) return;
			if (poll_readable(polls[0]))
			{
				char[128] dummy;
				sz? got = conn.read(&dummy);
				if (catch got) return;
				if (got == 0) return;
			}

			// Handle datagram from client -> forward to target.
			if (poll_readable(polls[1]))
			{
				char[128] src_sa;
				Socklen_t src_len = (Socklen_t)src_sa.len;
				sz got = recvfrom(client_sock.sock, &recv_buf, recv_buf.len, 0, (SockAddrPtr)&src_sa, &src_len);
				if (got >= 0)
				{
					proto::Address src_addr;
					if (decode_sockaddr_to_proto(src_sa[:src_len], &src_addr))
					{
						if (!client_pinned)
						{
							client_pinned = true;
							client_addr = src_addr;
							client_sa_len = src_len;
							mem::copy(&client_sa, &src_sa, (sz)src_len);
						}
						if (address_equals(src_addr, client_addr))
						{
							proto::UdpDatagram? dgram = proto::decode_udp_header(recv_buf[:got], tmem);
							if (catch dgram)
							{
								// malformed or fragmented: drop
							}
							else
							{
								char[128] target_sa;
								Socklen_t target_sa_len = 128;
								if (address_to_sockaddr(dgram.dst, target_sa[0..], &target_sa_len))
								{
									(void)sendto(target_sock.sock, dgram.payload.ptr, dgram.payload.len, 0, (SockAddrPtr)&target_sa, target_sa_len);
								}
							}
						}
					}
				}
			}

			// Handle datagram from target -> wrap and forward to client.
			if (poll_readable(polls[2]))
			{
				char[128] from_sa;
				Socklen_t from_len = (Socklen_t)from_sa.len;
				sz got = recvfrom(target_sock.sock, &recv_buf, recv_buf.len, 0, (SockAddrPtr)&from_sa, &from_len);
				if (got >= 0 && client_pinned)
				{
					proto::Address target_addr;
					if (decode_sockaddr_to_proto(from_sa[:from_len], &target_addr))
					{
						char[]? pkt = proto::encode_udp_header(tmem, target_addr, recv_buf[:got]);
						if (catch pkt)
						{
							// failed to encode: drop
						}
						else
						{
							(void)sendto(client_sock.sock, pkt.ptr, pkt.len, 0, (SockAddrPtr)&client_sa, client_sa_len);
						}
					}
				}
			}
		};
	}
}
