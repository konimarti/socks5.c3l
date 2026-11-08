// Tests for socks5::client against a fake SOCKS5 server on real loopback
// TCP: the fake server speaks the server side of the handshake using
// socks5::proto (decode_greeting/encode_method_selection/...), so these
// tests exercise the full client handshake end to end without needing the
// real server. Same two-module-block layout as relay_test.c3: helpers in
// the plain block, test functions in the @test block.
module socks5::client;

import std::net, std::net::tcp, std::io;
import socks5::proto, socks5::server;

<*
 BIND and UDP ASSOCIATE are tested against the real socks5::server, not
 a fake — RFC 1928's two-reply BIND handshake and the UDP relay's exact
 datagram framing are too easy to get subtly wrong on both ends of a
 hand-rolled fake and still agree with each other. Running the real
 server is the same "don't trust self-pairing alone" principle this
 project applies elsewhere, just within one process instead of against
 curl/ssh.

 Deliberately NOT Server.serve_forever(): that loop never returns, so
 the thread running it would outlive the test function — a Server
 struct on this function's stack would then be read by a thread after
 its frame is reused by the next test (this happened: a corrupted-
 mutex panic turned up in an unrelated LATER test, where the clobbered
 stack memory next got reused), and even heap-allocating it to dodge
 that just trades one problem for another (the per-test leak checker
 flags the intentionally-never-freed allocation as a leak). Instead,
 this accepts and fully handles exactly ONE connection via the same
 production handle_connection() serve_forever() itself calls, then
 returns — no infinite loop, nothing to outlive the test.
*>
struct OneShotArgs
{
	TcpServerSocket* listener;
	server::Server* config; // only allow_no_auth/auth_check are read; no .listen()/limiter needed
}

fn int run_one_connection(void* arg)
{
	OneShotArgs* a = (OneShotArgs*)arg;
	TcpSocket? c = tcp::accept(a.listener);
	if (catch c) return 1;
	TcpSocket conn = c;
	server::handle_connection(a.config, &conn);
	(void)conn.close();
	return 0;
}

struct FakeServerArgs
{
	TcpServerSocket* listener;
	bool require_auth;
	bool accept; // false => reply CONNECTION_REFUSED
	bool misbehave_unoffered_method; // reply GSSAPI regardless of what was offered
	// captured request, for assertions in the test after join
	bool got_request;
	proto::Command got_cmd;
	char[256] got_domain;
	usz got_domain_len;
	ushort got_port;
}

fn int fake_server(void* arg)
{
	FakeServerArgs* a = (FakeServerArgs*)arg;
	TcpSocket? conn = tcp::accept(a.listener);
	if (catch conn) return 1;
	// This runs on a spawned thread (see test_connect_* below); `tmem`
	// needs @pool_init here for the same reason server.c3's connection
	// threads do (see that file's module comment) — using `mem` instead
	// avoided the panic but leaked every allocation, since `mem` is a
	// plain heap allocator with no pool to reset.
	@pool_init(mem, 16384)
	{
	char[]? methods = proto::decode_greeting(&conn, tmem);
	if (catch methods) return 2;
	proto::Method selected = proto::Method.NO_ACCEPTABLE;
	if (a.misbehave_unoffered_method)
	{
		selected = proto::Method.GSSAPI; // never offered by the test client
	}
	else if (a.require_auth)
	{
		// This fake server demands username/password: fall through to
		// NO_ACCEPTABLE rather than NO_AUTH if the client didn't offer it.
		if (proto::methods_contains(methods, proto::Method.USERNAME_PASSWORD))
		{
			selected = proto::Method.USERNAME_PASSWORD;
		}
	}
	else if (proto::methods_contains(methods, proto::Method.NO_AUTH))
	{
		selected = proto::Method.NO_AUTH;
	}
	if (catch proto::encode_method_selection(&conn, selected)) return 3;
	if (selected == proto::Method.USERNAME_PASSWORD)
	{
		proto::UserpassRequest? req = proto::decode_userpass_request(&conn, tmem);
		if (catch req) return 4;
		bool ok = req.username == "alice" && req.password == "secret";
		if (catch proto::encode_userpass_reply(&conn, ok)) return 5;
		if (!ok)
		{
			(void)conn.close();
			return 0;
		}
	}
	proto::Request? req = proto::decode_request(&conn, tmem);
	if (catch req) return 6;
	a.got_request = true;
	a.got_cmd = req.cmd;
	a.got_port = req.dst.port;
	if (req.dst.atype == proto::AddressType.DOMAIN)
	{
		usz n = req.dst.domain.len;
		if (n > a.got_domain.len) n = a.got_domain.len;
		a.got_domain_len = n;
		for (usz i = 0; i < n; i++) a.got_domain[i] = req.dst.domain[i];
	}
	proto::ReplyCode code = a.accept ? proto::ReplyCode.SUCCEEDED : proto::ReplyCode.CONNECTION_REFUSED;
	proto::Address bnd = { .atype = proto::AddressType.IPV4, .ipv4 = { 127, 0, 0, 1 }, .port = 12345 };
	if (catch proto::encode_reply(&conn, code, bnd)) return 7;
	if (a.accept)
	{
		// Read until the client closes: proves the post-handshake socket is
		// live in both directions.
		char[64] buf;
		while (true)
		{
			sz? n = conn.read(&buf);
			if (catch n) break;
			if (n == 0) break;
		}
	}
	(void)conn.close();
	return 0;
	};
}

module socks5::client @test;

import std::net, std::net::tcp, std::net::os, std::thread, std::time;
import socks5::proto, socks5::server, socks5::acl, socks5::sockaddr;

macro void @expect_fault(#expr, fault want)
{
	if (catch err = #expr)
	{
		assert(err == want, "got %s, wanted %s", err, want);
		return;
	}
	assert(false, "expected fault %s but call succeeded", want);
}

fn void test_make_address_ipv4_vs_domain()
{
	proto::Address a = make_address("192.168.0.1", 1080);
	assert(a.atype == proto::AddressType.IPV4);
	assert(a.ipv4[0] == 192 && a.ipv4[3] == 1);
	assert(a.port == 1080);

	proto::Address d = make_address("example.com", 80);
	assert(d.atype == proto::AddressType.DOMAIN);
	assert(d.domain == "example.com");
	assert(d.port == 80);
}

fn void test_make_address_ipv6()
{
	proto::Address a = make_address("::1", 443);
	assert(a.atype == proto::AddressType.IPV6);
	assert(a.ipv6[15] == 1);
	assert(a.port == 443);
}

fn void test_connect_no_auth_success()
{
	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)listener.close();
	ushort port = listener.local_port()!!;
	FakeServerArgs args = { .listener = &listener, .require_auth = false, .accept = true };
	Thread t;
	t.create(&fake_server, &args)!!;

	TcpSocket sock = connect("127.0.0.1", (int)port, "example.com", (ushort)80)!!;
	sock.write("ping")!!; // socket must be live after the handshake
	(void)sock.close();
	t.join()!!;

	assert(args.got_request);
	assert(args.got_cmd == proto::Command.CONNECT);
	assert(args.got_domain_len == "example.com".len);
	assert((String)args.got_domain[:args.got_domain_len] == "example.com");
	assert(args.got_port == 80);
}

fn void test_connect_username_password_success()
{
	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)listener.close();
	ushort port = listener.local_port()!!;
	FakeServerArgs args = { .listener = &listener, .require_auth = true, .accept = true };
	Thread t;
	t.create(&fake_server, &args)!!;

	// IPv4 literal destination: must go out as ATYP=IPV4, not DOMAIN
	TcpSocket sock = connect("127.0.0.1", (int)port, "10.1.2.3", (ushort)443, "alice", "secret")!!;
	sock.write("ping")!!;
	(void)sock.close();
	t.join()!!;

	assert(args.got_request);
	assert(args.got_cmd == proto::Command.CONNECT);
	assert(args.got_domain_len == 0);
	assert(args.got_port == 443);
}

fn void test_connect_auth_rejected()
{
	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)listener.close();
	ushort port = listener.local_port()!!;
	FakeServerArgs args = { .listener = &listener, .require_auth = true, .accept = true };
	Thread t;
	t.create(&fake_server, &args)!!;

	@expect_fault(connect("127.0.0.1", (int)port, "example.com", (ushort)80, "alice", "wrong"), AUTH_FAILED);
	t.join()!!;
}

fn void test_connect_no_acceptable_methods()
{
	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)listener.close();
	ushort port = listener.local_port()!!;
	// server demands username/password, but the client offers NO_AUTH only
	FakeServerArgs args = { .listener = &listener, .require_auth = true, .accept = true };
	Thread t;
	t.create(&fake_server, &args)!!;

	@expect_fault(connect("127.0.0.1", (int)port, "example.com", (ushort)80), NO_ACCEPTABLE_METHODS);
	t.join()!!;
}

fn void test_connect_rejects_server_selecting_unoffered_method()
{
	// A server that selects a method the client never offered is
	// non-compliant (RFC 1928 section 3) — the client must not go
	// along with it (found by an independent red-team review,
	// reviews/client-review-v1.md, finding C-01).
	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)listener.close();
	ushort port = listener.local_port()!!;
	FakeServerArgs args = { .listener = &listener, .misbehave_unoffered_method = true, .accept = true };
	Thread t;
	t.create(&fake_server, &args)!!;

	@expect_fault(connect("127.0.0.1", (int)port, "example.com", (ushort)80), NO_ACCEPTABLE_METHODS);
	t.join()!!;
}

fn void test_connect_request_refused()
{
	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)listener.close();
	ushort port = listener.local_port()!!;
	FakeServerArgs args = { .listener = &listener, .require_auth = false, .accept = false };
	Thread t;
	t.create(&fake_server, &args)!!;

	@expect_fault(connect("127.0.0.1", (int)port, "example.com", (ushort)80), REQUEST_FAILED);
	t.join()!!;
}

fn void test_bind_round_trip_against_real_server()
{
	TcpServerSocket proxy_listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)proxy_listener.close();
	ushort proxy_port = proxy_listener.local_port()!!;

	server::Server config;
	config.allow_no_auth = true;
	OneShotArgs args = { .listener = &proxy_listener, .config = &config };
	Thread t;
	t.create(&run_one_connection, &args)!!;

	BindListener listener = bind("127.0.0.1", (int)proxy_port, "0.0.0.0", (ushort)0)!!;
	assert(listener.bound_addr.atype == IPV4, "expected IPV4 bind address on loopback");

	// The peer connects to the address the proxy reported in part 1.
	TcpSocket peer = tcp::connect("127.0.0.1", (int)listener.bound_addr.port)!!;
	BindConnection conn = bind_wait(&listener.control)!!;
	TcpSocket data_sock = conn.socket;
	assert(conn.peer_addr.atype == IPV4, "expected IPV4 peer address on loopback");

	data_sock.write("ping")!!;
	char[16] buf;
	sz n = peer.read(&buf)!!;
	assert((String)buf[:n] == "ping", "peer did not receive ping");

	peer.write("pong")!!;
	n = data_sock.read(&buf)!!;
	assert((String)buf[:n] == "pong", "client did not receive pong");

	// Closing both ends the handler's relay loop, letting
	// run_one_connection's thread return so join() doesn't hang.
	(void)peer.close();
	(void)data_sock.close();
	t.join()!!;
}

fn void test_udp_associate_round_trip_against_real_server()
{
	// The target address below is loopback (127.0.0.1), denied by the
	// default ACL (sprint 2) — same as the other UDP-to-loopback tests
	// in server_udp_test.c3, disable it for this test.
	acl::configure(true);
	defer acl::configure(false);

	// See test_bind_round_trip_against_real_server's comment: one
	// accepted connection, handled once, thread returns on its own —
	// no infinite serve_forever() loop to outlive this function.
	TcpServerSocket proxy_listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)proxy_listener.close();
	ushort proxy_port = proxy_listener.local_port()!!;

	server::Server config;
	config.allow_no_auth = true;
	OneShotArgs args = { .listener = &proxy_listener, .config = &config };
	Thread t;
	t.create(&run_one_connection, &args)!!;

	UdpAssociation assoc = udp_associate("127.0.0.1", (int)proxy_port)!!;

	Socket target = server::bind_udp_socket("127.0.0.1", 0, os::AF_INET)!!;
	defer (void)target.close();
	ushort target_port = target.local_port()!!;

	proto::Address target_addr = { .atype = IPV4, .ipv4 = { 127, 0, 0, 1 }, .port = target_port };
	char[] payload = "hello from client";
	char[] packet = proto::encode_udp_header(tmem, target_addr, payload)!!;

	char[128] relay_sa;
	Socklen_t relay_sa_len = 0;
	assert(sockaddr::address_to_sockaddr(assoc.relay_addr, relay_sa[0..], &relay_sa_len), "convert relay addr");

	// Send through a real UDP socket, not the control connection — the
	// relay address is a separate datagram socket (RFC 1928 section 7).
	Socket client_udp = server::bind_udp_socket("127.0.0.1", 0, os::AF_INET)!!;
	defer (void)client_udp.close();
	sz sent = server::sendto(client_udp.sock, packet.ptr, packet.len, 0, (SockAddrPtr)&relay_sa, relay_sa_len);
	assert(sent == (sz)packet.len, "sent datagram to relay");

	// Poll with a timeout rather than calling recvfrom directly: a
	// routing regression should fail this test, not hang it forever.
	Poll[1] target_poll = { { .socket = target.sock, .events = ANY_READ } };
	ulong target_ready = net::poll(target_poll[0..], time::sec(1))!!;
	assert(target_ready > 0, "target did not receive datagram within timeout");

	char[256] target_buf;
	char[128] from_sa;
	Socklen_t from_len = (Socklen_t)from_sa.len;
	sz got = server::recvfrom(target.sock, &target_buf, target_buf.len, 0, (SockAddrPtr)&from_sa, &from_len);
	assert(got == (sz)payload.len, "target received correct length");
	assert((String)target_buf[:got] == (String)payload, "target received correct payload");

	char[] reply = "hello from target";
	sz replied = server::sendto(target.sock, reply.ptr, reply.len, 0, (SockAddrPtr)&from_sa, from_len);
	assert(replied == (sz)reply.len, "target sent reply");

	Poll[1] client_poll = { { .socket = client_udp.sock, .events = ANY_READ } };
	ulong client_ready = net::poll(client_poll[0..], time::sec(1))!!;
	assert(client_ready > 0, "client did not receive reply datagram within timeout");

	char[256] client_buf;
	Socklen_t reply_from_len = (Socklen_t)128;
	char[128] reply_from_sa;
	got = server::recvfrom(client_udp.sock, &client_buf, client_buf.len, 0, (SockAddrPtr)&reply_from_sa, &reply_from_len);
	assert(got > 0, "client received reply datagram");

	proto::UdpDatagram reply_dgram = proto::decode_udp_header(client_buf[:got], tmem)!!;
	assert((String)reply_dgram.payload == (String)reply, "client received correct reply payload");

	// Closing the control connection ends the association (RFC 1928
	// section 7), letting run_one_connection's thread return so join()
	// doesn't hang.
	(void)assoc.control.close();
	t.join()!!;
}
