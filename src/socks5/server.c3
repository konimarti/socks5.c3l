// SOCKS5 server: accept loop, method negotiation, username/password
// authentication, and request dispatch. This file owns every byte read
// before a connection is trusted (RFC 1928 section 3-4 / RFC 1929); the
// per-command handlers in server_tcp.c3 and server_udp.c3 only run after
// negotiate_and_serve has already decoded and validated the request.
module socks5::server;

import std::net, std::net::tcp, std::thread, std::io, std::time;
import socks5::proto;

// Bound on every individual read during the pre-command handshake
// (greeting, username/password subnegotiation, request). The proxy faces
// unauthenticated clients directly at this stage, so a client that
// trickles bytes one at a time must not be able to pin a connection
// thread open indefinitely. Once a command is dispatched, data relay has
// no such deadline (same accepted limitation as ordinary proxy traffic:
// a genuinely idle established connection times out via
// socks5::relay::IDLE_TIMEOUT instead).
const Duration HANDSHAKE_TIMEOUT = (Duration)(10L * time::SEC);
const int LISTEN_BACKLOG = 64;

excuse
{
	NO_ACCEPTABLE_METHODS,
	AUTH_FAILED,
}

alias AuthCheckFn = fn bool(String username, String password);

struct Server
{
	TcpServerSocket listener;
	bool allow_no_auth;
	AuthCheckFn auth_check; // null => USERNAME_PASSWORD is never offered
}

<*
 Reads with a poll-enforced deadline (HANDSHAKE_TIMEOUT), wrapping the raw
 connection for the pre-command phase only. See the module comment above.
*>
struct DeadlineReader (InStream)
{
	Socket* sock;
}

fn sz? DeadlineReader.read(&self, char[] buffer) @dynamic
{
	Poll[1] polls = { { .socket = self.sock.sock, .events = ANY_READ } };
	ulong n = net::poll(polls[0..], HANDSHAKE_TIMEOUT)!;
	if (!n) return TIMEOUT~;
	return self.sock.read(buffer);
}

fn char? DeadlineReader.read_byte(&self) @dynamic
{
	char[1] b;
	sz got = self.read(&b)!;
	if (got == 0) return io::EOF~;
	return b[0];
}

fn Server*? Server.listen(&self, String host, int port)
{
	self.listener = tcp::listen(host, port, LISTEN_BACKLOG, REUSEADDR)!;
	return self;
}

<*
 Accept connections forever, one detached thread per connection. Returns
 only if the listening socket itself fails.
*>
fn void? Server.serve_forever(&self, bool allow_no_auth, AuthCheckFn auth_check)
{
	self.allow_no_auth = allow_no_auth;
	self.auth_check = auth_check;
	while (true)
	{
		TcpSocket? conn = tcp::accept(&self.listener);
		if (catch conn) continue; // a single failed accept must not stop the server
		ConnArgs* args = mem::new(ConnArgs, { .server = self, .conn = conn });
		Thread t;
		if (catch t.create(&handle_connection_thread, args))
		{
			(void)conn.close();
			mem::free(args);
			continue;
		}
		(void)t.detach();
	}
}

struct ConnArgs
{
	Server* server;
	TcpSocket conn;
}

fn int handle_connection_thread(void* arg)
{
	ConnArgs* args = (ConnArgs*)arg;
	Server* server = args.server;
	TcpSocket conn = args.conn;
	mem::free(args);
	handle_connection(server, &conn);
	(void)conn.close();
	return 0;
}

fn void handle_connection(Server* server, TcpSocket* conn)
{
	// Each connection runs on its own spawned thread (see
	// Server.serve_forever); `tmem` is only auto-created on the main
	// thread — plain `@pool()` isn't enough either, it derives from that
	// same on-demand allocator internally. `@pool_init` creates one from
	// scratch, which is what every call in this connection's lifetime
	// that uses `tmem` (decode_greeting, decode_userpass_request,
	// decode_request, and whatever the command handlers use, up to a
	// 65507-byte UDP datagram) needs, for the whole connection.
	@pool_init(mem, 65536)
	{
		DeadlineReader dr = { .sock = (Socket*)conn };
		// Any protocol, auth, or I/O fault during negotiation: drop the
		// connection silently, matching ordinary proxy behaviour (RFC 1928
		// does not define an error channel before the method is selected).
		if (catch negotiate_and_serve(server, conn, &dr)) return;
	};
}

fn void? negotiate_and_serve(Server* server, TcpSocket* conn, InStream in)
{
	Method selected = negotiate_method(server, in, conn)!;
	if (selected == USERNAME_PASSWORD) authenticate(server, in, conn)!;
	proto::Request req = proto::decode_request(in, tmem)!;
	dispatch(conn, req);
}

fn Method? negotiate_method(Server* server, InStream in, OutStream out)
{
	char[] methods = proto::decode_greeting(in, tmem)!;
	Method selected = NO_ACCEPTABLE;
	if (server.auth_check && proto::methods_contains(methods, USERNAME_PASSWORD))
	{
		selected = USERNAME_PASSWORD;
	}
	else if (server.allow_no_auth && proto::methods_contains(methods, NO_AUTH))
	{
		selected = NO_AUTH;
	}
	proto::encode_method_selection(out, selected)!;
	if (selected == NO_ACCEPTABLE) return NO_ACCEPTABLE_METHODS~;
	return selected;
}

fn void? authenticate(Server* server, InStream in, OutStream out)
{
	proto::UserpassRequest req = proto::decode_userpass_request(in, tmem)!;
	bool ok = server.auth_check(req.username, req.password);
	proto::encode_userpass_reply(out, ok)!;
	if (!ok) return AUTH_FAILED~;
}

fn void dispatch(TcpSocket* conn, proto::Request req)
{
	switch (req.cmd)
	{
		case CONNECT:       handle_connect(conn, req.dst);
		case BIND:          handle_bind(conn, req.dst);
		case UDP_ASSOCIATE:  handle_udp_associate(conn, req.dst);
	}
}
