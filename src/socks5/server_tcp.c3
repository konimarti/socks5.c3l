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

import std::net, std::net::tcp;
import socks5::proto;

fn void handle_connect(TcpSocket* conn, proto::Address dst)
{
	Address fallback;
	(void)proto::encode_reply(conn, COMMAND_NOT_SUPPORTED, fallback);
}

fn void handle_bind(TcpSocket* conn, proto::Address dst)
{
	Address fallback;
	(void)proto::encode_reply(conn, COMMAND_NOT_SUPPORTED, fallback);
}
