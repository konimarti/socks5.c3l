// SOCKS5 client: dial a proxy over TCP, negotiate an auth method, optionally
// run the RFC 1929 username/password subnegotiation, send a request, and hand
// back the resulting socket. This mirrors the negotiation half of
// socks5::server from the other side of the wire; every byte on the wire goes
// through socks5::proto, so the client and server share one codec.
module socks5::client;

import std::net, std::net::tcp, std::io, std::time;
import socks5::proto;

// Deadline for establishing the TCP connection to the proxy itself. The
// handshake after connect() returns is the caller's business, same accepted
// limitation as the server's post-dispatch data phase.
const Duration CONNECT_TIMEOUT = (Duration)(10L * time::SEC);

excuse
{
	NO_ACCEPTABLE_METHODS, // server selected 0xff, or a method this client cannot perform
	AUTH_FAILED,           // username/password subnegotiation returned failure
	REQUEST_FAILED,        // reply REP was not SUCCEEDED
}

<*
 Dial the proxy itself over TCP.
*>
fn TcpSocket? dial(String proxy_host, int proxy_port)
{
	return tcp::connect(proxy_host, proxy_port, CONNECT_TIMEOUT);
}

<*
 Offer `methods` in the greeting and read the server's method selection.
 @return? NO_ACCEPTABLE_METHODS : "server selected 0xff or a method we cannot perform"
*>
fn Method? negotiate_method(TcpSocket* sock, Method[] methods)
{
	proto::encode_greeting(sock, methods)!;
	Method selected = proto::decode_method_selection(sock)!;
	switch (selected)
	{
		case NO_AUTH:
		case USERNAME_PASSWORD:
			return selected;
		default:
			return NO_ACCEPTABLE_METHODS~;
	}
}

<*
 RFC 1929 username/password subnegotiation.
 @return? AUTH_FAILED : "server replied with a non-zero status"
*>
fn void? authenticate(TcpSocket* sock, String username, String password)
{
	proto::encode_userpass_request(sock, username, password)!;
	bool ok = proto::decode_userpass_reply(sock)!;
	if (!ok) return AUTH_FAILED~;
}

<*
 Send a request and read the server's full reply (REP code + BND.ADDR).
 The reply's domain, if any, is allocated with tmem.
*>
fn proto::Reply? send_request(TcpSocket* sock, proto::Command cmd, proto::Address dst)
{
	proto::encode_request(sock, cmd, dst)!;
	return proto::decode_reply(sock, tmem);
}

<*
 Build a DST.ADDR from a host string: a dotted-quad IPv4 literal goes out as
 IPV4, anything else as DOMAIN (the proxy resolves it — this also covers
 IPv6 literals, which getaddrinfo resolves on the proxy side).
*>
fn proto::Address make_address(String host, ushort port)
{
	InetAddress? ip = net::ipv4_from_str(host);
	if (catch ip)
	{
		return { .atype = proto::AddressType.DOMAIN, .domain = host, .port = port };
	}
	return {
		.atype = proto::AddressType.IPV4,
		.ipv4 = { ip.ipv4.a, ip.ipv4.b, ip.ipv4.c, ip.ipv4.d },
		.port = port,
	};
}

<*
 Full CONNECT handshake: dial the proxy, negotiate a method (offering
 USERNAME_PASSWORD in addition to NO_AUTH when credentials are given),
 authenticate if the server picked it, send CONNECT for the destination, and
 return the connected socket. The socket is closed if any step faults.
 @param username : "empty => offer NO_AUTH only"
 @return? NO_ACCEPTABLE_METHODS
 @return? AUTH_FAILED
 @return? REQUEST_FAILED : "proxy replied with a non-SUCCEEDED REP code"
*>
fn TcpSocket? connect(String proxy_host, int proxy_port, String dst_host, ushort dst_port, String username = "", String password = "")
{
	TcpSocket sock = dial(proxy_host, proxy_port)!;
	TcpSocket? result = connect_over(&sock, dst_host, dst_port, username, password);
	if (catch err = result)
	{
		(void)sock.close();
		return err~;
	}
	return sock;
}

fn TcpSocket? connect_over(TcpSocket* sock, String dst_host, ushort dst_port, String username, String password)
{
	Method[2] offered = { NO_AUTH, USERNAME_PASSWORD };
	Method[] methods = offered[:1];
	if (username.len > 0) methods = offered[0..];
	Method selected = negotiate_method(sock, methods)!;
	if (selected == USERNAME_PASSWORD) authenticate(sock, username, password)!;
	proto::Reply reply = send_request(sock, proto::Command.CONNECT, make_address(dst_host, dst_port))!;
	if (reply.code != proto::ReplyCode.SUCCEEDED) return REQUEST_FAILED~;
	return *sock;
}
