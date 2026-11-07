// Tests for socks5::client against a fake SOCKS5 server on real loopback
// TCP: the fake server speaks the server side of the handshake using
// socks5::proto (decode_greeting/encode_method_selection/...), so these
// tests exercise the full client handshake end to end without needing the
// real server. Same two-module-block layout as relay_test.c3: helpers in
// the plain block, test functions in the @test block.
module socks5::client;

import std::net, std::net::tcp, std::io;
import socks5::proto;

struct FakeServerArgs
{
	TcpServerSocket* listener;
	bool require_auth;
	bool accept; // false => reply CONNECTION_REFUSED
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
	char[]? methods = proto::decode_greeting(&conn, mem);
	if (catch methods) return 2;
	proto::Method selected = proto::Method.NO_ACCEPTABLE;
	if (a.require_auth)
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
		proto::UserpassRequest? req = proto::decode_userpass_request(&conn, mem);
		if (catch req) return 4;
		bool ok = req.username == "alice" && req.password == "secret";
		if (catch proto::encode_userpass_reply(&conn, ok)) return 5;
		if (!ok)
		{
			(void)conn.close();
			return 0;
		}
	}
	proto::Request? req = proto::decode_request(&conn, mem);
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
}

module socks5::client @test;

import std::net, std::net::tcp, std::thread;
import socks5::proto;

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
