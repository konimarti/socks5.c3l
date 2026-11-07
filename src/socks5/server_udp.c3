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

import std::net, std::net::tcp;
import socks5::proto;

fn void handle_udp_associate(TcpSocket* conn, proto::Address client_hint)
{
	Address fallback;
	(void)proto::encode_reply(conn, COMMAND_NOT_SUPPORTED, fallback);
}
