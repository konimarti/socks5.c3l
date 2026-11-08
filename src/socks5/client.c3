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
	// RFC 1928 section 3: the server picks from the methods WE offered.
	// A server that returns something else (whether a known method we
	// never offered, or an unrecognized byte) is non-compliant, not
	// something to go along with.
	bool offered = false;
	foreach (Method m : methods) if (m == selected) offered = true;
	if (!offered) return NO_ACCEPTABLE_METHODS~;
	return selected;
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
 Build a DST.ADDR from a host string: a dotted-quad IPv4 literal or a
 colon-form IPv6 literal goes out as IPV4/IPV6 respectively (a remote
 DNS-resolving proxy can't resolve either as a domain name — trying to
 send a literal address through as DOMAIN would fail against most real
 proxies); anything else goes out as DOMAIN for the proxy to resolve.
*>
fn proto::Address make_address(String host, ushort port)
{
	InetAddress? ip4 = net::ipv4_from_str(host);
	if (try ip = ip4)
	{
		return {
			.atype = proto::AddressType.IPV4,
			.ipv4 = { ip.ipv4.a, ip.ipv4.b, ip.ipv4.c, ip.ipv4.d },
			.port = port,
		};
	}
	InetAddress? ip6 = net::ipv6_from_str(host);
	if (try ip = ip6)
	{
		proto::Address addr = { .atype = proto::AddressType.IPV6, .port = port };
		mem::copy(&addr.ipv6, &ip.ipv6, 16);
		return addr;
	}
	return { .atype = proto::AddressType.DOMAIN, .domain = host, .port = port };
}

// Threading note: this uses `tmem` (directly, and indirectly via
// std::net::addrinfo's own @pool()). Call it from the main thread, or
// from a thread whose entry point has already wrapped its body in
// @pool_init(mem, <size>) -- do NOT call it from a bare spawned thread
// with no pool established, and do not wrap it in another @pool_init
// yourself: @pool_init requires no pool already exist, which breaks
// the common case of calling connect() from the main thread. See
// server.c3's module comment for why connection-handling threads need
// this at all.
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

<*
 The negotiate-then-optionally-authenticate sequence every command
 shares, factored out so CONNECT/BIND/UDP_ASSOCIATE don't each
 reimplement it.
*>
fn void? handshake(TcpSocket* sock, String username, String password)
{
	Method[2] offered = { NO_AUTH, USERNAME_PASSWORD };
	Method[] methods = offered[:1];
	if (username.len > 0) methods = offered[0..];
	Method selected = negotiate_method(sock, methods)!;
	if (selected == USERNAME_PASSWORD) authenticate(sock, username, password)!;
}

fn TcpSocket? connect_over(TcpSocket* sock, String dst_host, ushort dst_port, String username, String password)
{
	handshake(sock, username, password)!;
	proto::Reply reply = send_request(sock, proto::Command.CONNECT, make_address(dst_host, dst_port))!;
	if (reply.code != proto::ReplyCode.SUCCEEDED) return REQUEST_FAILED~;
	return *sock;
}

<*
 The control connection and listening address for an in-progress BIND
 (RFC 1928 section 4/6). `bound_addr` is where the proxy is now
 listening — hand it to whatever needs to connect there (e.g. an FTP
 PORT command) — then call bind_wait() on `control` to block for that
 peer and get a socket ready to relay data with it.
*>
struct BindListener
{
	TcpSocket control;
	proto::Address bound_addr;
}

<*
 RFC 1928 BIND, part 1: dial, handshake, send BIND for `dst_host:
 dst_port` (the peer address the proxy expects — many real proxies
 accept any peer regardless), and return the listening address from
 the first reply.
 @return? NO_ACCEPTABLE_METHODS
 @return? AUTH_FAILED
 @return? REQUEST_FAILED : "the first BIND reply was not SUCCEEDED"
*>
fn BindListener? bind(String proxy_host, int proxy_port, String dst_host, ushort dst_port, String username = "", String password = "")
{
	TcpSocket sock = dial(proxy_host, proxy_port)!;
	BindListener? result = bind_over(&sock, dst_host, dst_port, username, password);
	if (catch err = result)
	{
		(void)sock.close();
		return err~;
	}
	return result;
}

fn BindListener? bind_over(TcpSocket* sock, String dst_host, ushort dst_port, String username, String password)
{
	handshake(sock, username, password)!;
	proto::Reply reply = send_request(sock, proto::Command.BIND, make_address(dst_host, dst_port))!;
	if (reply.code != proto::ReplyCode.SUCCEEDED) return REQUEST_FAILED~;
	return { .control = *sock, .bound_addr = reply.bnd };
}

<*
 RFC 1928 BIND, part 2: block for the proxy's second reply (sent once a
 peer connects to the address from part 1), and return the same
 control socket, now ready to relay data with that peer. Closes and
 returns a fault if the second reply isn't SUCCEEDED.
 @return? REQUEST_FAILED : "the second BIND reply was not SUCCEEDED"
*>
fn TcpSocket? bind_wait(TcpSocket* sock)
{
	proto::Reply reply = proto::decode_reply(sock, tmem)!;
	if (reply.code != proto::ReplyCode.SUCCEEDED)
	{
		(void)sock.close();
		return REQUEST_FAILED~;
	}
	return *sock;
}

<*
 The control connection and relay address for an in-progress UDP
 ASSOCIATE (RFC 1928 section 7). Wrap each outgoing datagram with
 proto::encode_udp_header and send it to `relay_addr`; unwrap incoming
 replies with proto::decode_udp_header. `control` must stay open for
 as long as the association is needed — closing it tears the relay
 down, same as the server side.
*>
struct UdpAssociation
{
	TcpSocket control;
	proto::Address relay_addr;
}

<*
 RFC 1928 UDP ASSOCIATE: dial, handshake, send UDP_ASSOCIATE advertising
 `client_host:client_port` as this client's own UDP source (0.0.0.0:0,
 the defaults, is fine — most proxies don't require a real one), and
 return the relay address from the reply.
 @return? NO_ACCEPTABLE_METHODS
 @return? AUTH_FAILED
 @return? REQUEST_FAILED : "the UDP ASSOCIATE reply was not SUCCEEDED"
*>
fn UdpAssociation? udp_associate(String proxy_host, int proxy_port, String client_host = "0.0.0.0", ushort client_port = 0, String username = "", String password = "")
{
	TcpSocket sock = dial(proxy_host, proxy_port)!;
	UdpAssociation? result = udp_associate_over(&sock, client_host, client_port, username, password);
	if (catch err = result)
	{
		(void)sock.close();
		return err~;
	}
	return result;
}

fn UdpAssociation? udp_associate_over(TcpSocket* sock, String client_host, ushort client_port, String username, String password)
{
	handshake(sock, username, password)!;
	proto::Reply reply = send_request(sock, proto::Command.UDP_ASSOCIATE, make_address(client_host, client_port))!;
	if (reply.code != proto::ReplyCode.SUCCEEDED) return REQUEST_FAILED~;
	return { .control = *sock, .relay_addr = reply.bnd };
}
