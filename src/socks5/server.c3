// SOCKS5 server: accept loop, method negotiation, username/password
// authentication, and request dispatch. This file owns every byte read
// before a connection is trusted (RFC 1928 section 3-4 / RFC 1929); the
// per-command handlers in server_tcp.c3 and server_udp.c3 only run after
// negotiate_and_serve has already decoded and validated the request.
module socks5::server;

import std::net, std::net::tcp, std::thread, std::io, std::time, std::time::clock;
import socks5::proto;

// Bound on the WHOLE pre-command handshake (greeting, username/password
// subnegotiation, request), not each individual read — a per-read-only
// deadline still lets a client trickle one byte every (just under)
// HANDSHAKE_TIMEOUT seconds and pin a thread open indefinitely, which is
// exactly the bug this constant's name promises to prevent. See
// DeadlineReader, which measures elapsed time from connection start.
// Once a command is dispatched, data relay has no such deadline (same
// accepted limitation as ordinary proxy traffic: a genuinely idle
// established connection times out via socks5::relay::IDLE_TIMEOUT
// instead).
const Duration HANDSHAKE_TIMEOUT = (Duration)(10L * time::SEC);
const int LISTEN_BACKLOG = 64;

// A connection flood with no cap spawns one OS thread per connection
// until the process runs out of memory or thread handles — the single
// highest-impact gap for running this somewhere actually exposed to
// untrusted clients. serve_forever() takes the caller's chosen limit
// explicitly; this is just a sane default for callers that don't have
// a more specific number in mind.
const usz DEFAULT_MAX_CONNECTIONS = 1024;

excuse
{
	NO_ACCEPTABLE_METHODS,
	AUTH_FAILED,
}

alias AuthCheckFn = fn bool(String username, String password);

<*
 A simple counting limiter: try_acquire() fails (returns false) once
 `max` connections are concurrently held. One mutex, no condition
 variable — serve_forever rejects immediately rather than queuing, so
 nothing ever needs to wait on a release.
*>
struct ConnLimiter
{
	Mutex lock;
	usz current;
	usz max;
}

fn void ConnLimiter.init(&self, usz max)
{
	self.lock.init()!!;
	self.max = max;
	self.current = 0;
}

fn bool ConnLimiter.try_acquire(&self)
{
	self.lock.lock()!!;
	defer self.lock.unlock();
	if (self.current >= self.max) return false;
	self.current++;
	return true;
}

fn void ConnLimiter.release(&self)
{
	self.lock.lock()!!;
	defer self.lock.unlock();
	// A release() with no matching acquire (a future bug, not a case
	// that exists today) would otherwise underflow this usz to
	// usz::max, which permanently locks try_acquire() into rejecting
	// every connection. Guarding costs nothing and turns that failure
	// mode into a no-op instead.
	if (self.current > 0) self.current--;
}

struct Server
{
	TcpServerSocket listener;
	bool allow_no_auth;
	AuthCheckFn auth_check; // null => USERNAME_PASSWORD is never offered
	ConnLimiter limiter;
}

<*
 Reads with a poll-enforced deadline covering the whole pre-command
 phase (HANDSHAKE_TIMEOUT total, from `start`, not per read). See the
 module comment above.
*>
struct DeadlineReader (InStream)
{
	Socket* sock;
	Clock start;
}

fn Duration DeadlineReader.remaining(&self)
{
	Duration elapsed = self.start.to_now().to_duration();
	if (elapsed >= HANDSHAKE_TIMEOUT) return (Duration)0;
	return HANDSHAKE_TIMEOUT - elapsed;
}

fn sz? DeadlineReader.read(&self, char[] buffer) @dynamic
{
	Duration left = self.remaining();
	if (left <= (Duration)0) return TIMEOUT~;
	Poll[1] polls = { { .socket = self.sock.sock, .events = ANY_READ } };
	ulong n = net::poll(polls[0..], left)!;
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
 Accept connections forever, one detached thread per connection, up to
 `max_connections` concurrently — beyond that, a new connection is
 accepted (so the listen backlog doesn't back up) and closed immediately
 without running any SOCKS5 negotiation. Returns only if the listening
 socket itself fails.
*>
fn void? Server.serve_forever(&self, bool allow_no_auth, AuthCheckFn auth_check, usz max_connections = DEFAULT_MAX_CONNECTIONS)
{
	self.allow_no_auth = allow_no_auth;
	self.auth_check = auth_check;
	self.limiter.init(max_connections);
	while (true)
	{
		TcpSocket? conn = tcp::accept(&self.listener);
		if (catch conn) continue; // a single failed accept must not stop the server
		if (!self.limiter.try_acquire())
		{
			(void)conn.close();
			continue;
		}
		ConnArgs* args = mem::new(ConnArgs, { .server = self, .conn = conn });
		Thread t;
		if (catch t.create(&handle_connection_thread, args))
		{
			(void)conn.close();
			mem::free(args);
			self.limiter.release();
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
	server.limiter.release();
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
		DeadlineReader dr = { .sock = (Socket*)conn, .start = clock::now() };
		// Any protocol, auth, or I/O fault before the request is decoded:
		// drop the connection silently, matching ordinary proxy behaviour
		// (RFC 1928 does not define an error channel before the method is
		// selected, and a fault here means we don't have a well-formed
		// request to reply to in the first place).
		if (catch negotiate_and_serve(server, conn, &dr)) return;
	};
}

fn void? negotiate_and_serve(Server* server, TcpSocket* conn, InStream in)
{
	Method selected = negotiate_method(server, in, conn)!;
	if (selected == USERNAME_PASSWORD) authenticate(server, in, conn)!;

	// Unlike the greeting/auth faults above, an unsupported CMD or ATYP
	// (RFC 1928 section 6) has a defined reply — COMMAND_NOT_SUPPORTED
	// (0x07) / ADDRESS_TYPE_NOT_SUPPORTED (0x08) — rather than a silent
	// drop. decode_request faults before VER/RSV are fully malformed and
	// still get dropped silently (no address to reply to the client).
	proto::Request? req = proto::decode_request(in, tmem);
	if (catch err = req)
	{
		Address empty = { .atype = IPV4 };
		switch (err)
		{
			case proto::UNSUPPORTED_COMMAND:
				(void)proto::encode_reply(conn, COMMAND_NOT_SUPPORTED, empty);
			case proto::UNSUPPORTED_ADDRESS_TYPE:
				(void)proto::encode_reply(conn, ADDRESS_TYPE_NOT_SUPPORTED, empty);
			default:
		}
		return err~;
	}
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
