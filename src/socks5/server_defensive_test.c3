// Defensive behavior and timeout tests:
// 1. Socks5ConnLimiter: max concurrent connections cap rejection and slot reuse.
// 2. HANDSHAKE_TIMEOUT: slow-loris / stalling pre-command client cutoff.
// 3. BIND_TIMEOUT: bounded wait when no rendezvous peer connects to bound port.
module socks5::server;

import std::net, std::net::tcp, std::thread, std::time;
import socks5::proto;

struct ServerRunArgs
{
	Socks5Server* server;
	usz max_conn;
}

fn int run_serve_forever_thread(void* arg)
{
	@pool_init(mem, 65536)
	{
		ServerRunArgs* a = (ServerRunArgs*)arg;
		(void)a.server.serve_forever(true, null, a.max_conn);
	};
	return 0;
}

struct ConnThreadArgs
{
	Socks5Server* server;
	TcpSocket conn;
}

fn int run_conn_thread(void* arg)
{
	ConnThreadArgs* a = (ConnThreadArgs*)arg;
	handle_connection(a.server, &a.conn);
	(void)a.conn.close();
	return 0;
}

<*
 Polls server.limiter.current down to `want` instead of a fixed sleep.
 The per-connection threads serve_forever() spawns are detached (fire
 and forget, by design — production has no caller to join them) and
 limiter.release() is the last thing one touches on `server` before
 returning, so waiting for the count to settle is really waiting for
 those threads to be done touching this stack-local server at all:
 a fixed sleep before stack teardown would be a stack-use-after-return
 race, the same bug class client_test.c3 already hit once this project.
*>
fn void wait_for_limiter_count(Socks5Server* server, usz want, uint timeout_ms)
{
	uint waited = 0;
	while (server.limiter.current != want && waited < timeout_ms)
	{
		thread::sleep_ms(2);
		waited += 2;
	}
}

module socks5::server @test;

import std::net, std::net::tcp, std::thread, std::io, std::time;
import socks5::proto;

<*
 Verifies that Socks5ConnLimiter enforces max_connections against real concurrent
 clients. Excess connections beyond the limit are accepted and closed immediately
 without negotiation. Once an active connection terminates, its slot is freed and
 a new connection can connect and negotiate successfully.
*>
fn void test_conn_limiter_rejects_excess_connections()
{
	Socks5Server server;
	server.listen("127.0.0.1", 0)!!;
	ushort port = server.listener.local_port()!!;

	ServerRunArgs args = { .server = &server, .max_conn = 2 };
	Thread server_t;
	server_t.create(&run_serve_forever_thread, &args)!!;

	char[] greeting = { proto::VERSION, 1, proto::Socks5Method.NO_AUTH.wire };

	// 1. Client 1 connects and holds slot 1
	TcpSocket client1 = tcp::connect("127.0.0.1", port)!!;
	defer (void)client1.close();
	client1.write(greeting)!!;
	char[2] sel1;
	io::read_all(&client1, &sel1)!!;
	assert(sel1[0] == proto::VERSION);
	assert(sel1[1] == proto::Socks5Method.NO_AUTH.wire);

	// 2. Client 2 connects and holds slot 2 (limiter now at capacity: 2/2)
	TcpSocket client2 = tcp::connect("127.0.0.1", port)!!;
	defer (void)client2.close();
	client2.write(greeting)!!;
	char[2] sel2;
	io::read_all(&client2, &sel2)!!;
	assert(sel2[0] == proto::VERSION);
	assert(sel2[1] == proto::Socks5Method.NO_AUTH.wire);

	// 3. Client 3 attempts to connect while limiter is full.
	TcpSocket client3 = tcp::connect("127.0.0.1", port)!!;
	defer (void)client3.close();

	// Server accepts and immediately closes conn without SOCKS5 negotiation.
	// Client 3 should receive EOF (0 bytes or connection reset) when reading.
	(void)client3.write(greeting);
	Poll[1] p3 = { { .socket = client3.sock, .events = ANY_READ } };
	ulong ready3 = net::poll(p3[0..], time::ms(500))!!;
	assert(ready3 > 0);

	char[2] sel3;
	sz? got3 = client3.read(&sel3);
	bool closed3 = false;
	if (catch got3)
	{
		closed3 = true;
	}
	else if (got3 == 0)
	{
		closed3 = true;
	}
	assert(closed3, "excess connection should be closed immediately");

	// 4. Close client 1 to release one slot.
	(void)client1.close();

	// Wait for client 1's connection thread to finish and call limiter.release()
	wait_for_limiter_count(&server, 1, 1000);

	// 5. Client 4 connects now and should succeed
	TcpSocket client4 = tcp::connect("127.0.0.1", port)!!;
	defer (void)client4.close();
	client4.write(greeting)!!;
	char[2] sel4;
	io::read_all(&client4, &sel4)!!;
	assert(sel4[0] == proto::VERSION);
	assert(sel4[1] == proto::Socks5Method.NO_AUTH.wire);

	// Teardown: wait for both remaining connection threads to finish and
	// release their slots before server (stack-local) goes out of scope.
	// serve_forever's per-connection threads are detached, so nothing
	// else makes this deterministic -- see wait_for_limiter_count's doc.
	(void)client2.close();
	(void)client4.close();
	wait_for_limiter_count(&server, 0, 1000);

	server.stop();
	server_t.join()!!;
}

<*
 Verifies that Socks5DeadlineReader disconnects slow-loris clients that trickle
 bytes too slowly during the pre-command handshake.
*>
fn void test_handshake_timeout_disconnects_slow_client()
{
	configure_handshake_timeout(time::ms(80));
	defer configure_handshake_timeout(DEFAULT_HANDSHAKE_TIMEOUT);

	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)listener.close();
	ushort port = listener.local_port()!!;

	TcpSocket client = tcp::connect("127.0.0.1", port)!!;
	defer (void)client.close();

	TcpSocket conn = tcp::accept(&listener)!!;

	Socks5Server server;
	server.allow_no_auth = true;
	ConnThreadArgs args = { .server = &server, .conn = conn };
	Thread t;
	t.create(&run_conn_thread, &args)!!;

	// Slow-loris: send 1 byte of greeting (0x05) and stall
	char[1] one_byte = { proto::VERSION };
	client.write(&one_byte)!!;

	// Wait for server deadline (80ms) to expire. Server should close conn.
	Poll[1] p = { { .socket = client.sock, .events = ANY_READ } };
	ulong ready = net::poll(p[0..], time::ms(500))!!;
	assert(ready > 0);

	char[10] buf;
	sz? got = client.read(&buf);
	bool closed = false;
	if (catch got)
	{
		closed = true;
	}
	else if (got == 0)
	{
		closed = true;
	}
	assert(closed, "server should close connection on handshake timeout");

	t.join()!!;
}

<*
 Verifies that a normal fast client completes handshake successfully under the
 configured handshake deadline.
*>
fn void test_handshake_timeout_fast_client_succeeds()
{
	configure_handshake_timeout(time::ms(80));
	defer configure_handshake_timeout(DEFAULT_HANDSHAKE_TIMEOUT);

	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)listener.close();
	ushort port = listener.local_port()!!;

	TcpSocket client = tcp::connect("127.0.0.1", port)!!;
	defer (void)client.close();

	TcpSocket conn = tcp::accept(&listener)!!;

	Socks5Server server;
	server.allow_no_auth = true;
	ConnThreadArgs args = { .server = &server, .conn = conn };
	Thread t;
	t.create(&run_conn_thread, &args)!!;

	// Send full greeting immediately
	char[] greeting = { proto::VERSION, 1, proto::Socks5Method.NO_AUTH.wire };
	client.write(greeting)!!;

	char[2] sel;
	io::read_all(&client, &sel)!!;
	assert(sel[0] == proto::VERSION);
	assert(sel[1] == proto::Socks5Method.NO_AUTH.wire);

	// Unsupported command triggers immediate reply and clean completion
	char[] req = { proto::VERSION, 0x09, 0, (char)proto::Socks5AddressType.IPV4.wire, 127, 0, 0, 1, 0, 80 };
	client.write(req)!!;

	char[3] reply_head;
	io::read_all(&client, &reply_head)!!;
	assert(reply_head[1] == proto::Socks5ReplyCode.COMMAND_NOT_SUPPORTED.wire);

	t.join()!!;
}

<*
 Verifies that handle_bind enforces BIND_TIMEOUT: when a client requests BIND,
 the server replies with the bound port, but if no external rendezvous peer
 connects within BIND_TIMEOUT, the server sends Reply 2 with GENERAL_FAILURE
 and terminates the connection.
*>
fn void test_bind_timeout_replies_general_failure()
{
	configure_bind_timeout(time::ms(80));
	defer configure_bind_timeout(DEFAULT_BIND_TIMEOUT);

	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)listener.close();
	ushort port = listener.local_port()!!;

	TcpSocket client = tcp::connect("127.0.0.1", port)!!;
	defer (void)client.close();

	TcpSocket conn = tcp::accept(&listener)!!;

	Socks5Server server;
	server.allow_no_auth = true;
	ConnThreadArgs args = { .server = &server, .conn = conn };
	Thread t;
	t.create(&run_conn_thread, &args)!!;

	// 1. Handshake greeting
	char[] greeting = { proto::VERSION, 1, proto::Socks5Method.NO_AUTH.wire };
	client.write(greeting)!!;
	char[2] sel;
	io::read_all(&client, &sel)!!;
	assert(sel[1] == proto::Socks5Method.NO_AUTH.wire);

	// 2. Request BIND (0.0.0.0:0)
	proto::Socks5Address dst = { .atype = IPV4, .ipv4 = { 0, 0, 0, 0 }, .port = 0 };
	proto::encode_request((OutStream)&client, BIND, dst)!!;

	// 3. First reply: SUCCEEDED with bound ephemeral port
	proto::Socks5Reply rep1 = proto::decode_reply((InStream)&client, tmem)!!;
	assert(rep1.code == SUCCEEDED);
	assert(rep1.bnd.port > 0);

	// 4. Do NOT dial rep1.bnd.port. Wait for second reply after BIND_TIMEOUT (80ms).
	proto::Socks5Reply rep2 = proto::decode_reply((InStream)&client, tmem)!!;
	assert(rep2.code == GENERAL_FAILURE, "expected GENERAL_FAILURE on BIND timeout");

	// 5. Server should close connection after failure
	char[10] buf;
	sz? got = client.read(&buf);
	bool closed = false;
	if (catch got)
	{
		closed = true;
	}
	else if (got == 0)
	{
		closed = true;
	}
	assert(closed, "server should close connection after BIND failure");

	t.join()!!;
}
