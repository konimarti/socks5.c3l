module socks5::server;

import std::net, std::net::tcp, std::thread;
import socks5::proto;

struct ConnectArgs
{
	TcpSocket* conn;
	proto::Address dst;
}

fn int run_connect_thread(void* arg)
{
	@pool_init(mem, 16384)
	{
		ConnectArgs* args = (ConnectArgs*)arg;
		handle_connect(args.conn, args.dst);
	};
	return 0;
}

struct BindArgs
{
	TcpSocket* conn;
	proto::Address dst;
}

fn int run_bind_thread(void* arg)
{
	@pool_init(mem, 16384)
	{
		BindArgs* args = (BindArgs*)arg;
		handle_bind(args.conn, args.dst);
	};
	return 0;
}

module socks5::server @test;

import std::net, std::net::tcp, std::thread, std::io;
import socks5::proto;
import socks5::acl;

fn void test_connect_ipv4_success()
{
	acl::configure(true);
	defer acl::configure(false);

	// 1. Target listener
	TcpServerSocket target_server = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)target_server.close();
	ushort target_port = target_server.local_port()!!;

	// 2. Client-to-proxy connection pair
	TcpServerSocket proxy_server = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)proxy_server.close();
	ushort proxy_port = proxy_server.local_port()!!;

	TcpSocket client = tcp::connect("127.0.0.1", proxy_port)!!;
	defer (void)client.close();
	TcpSocket proxy_conn = tcp::accept(&proxy_server)!!;
	defer (void)proxy_conn.close();

	// 3. Run handle_connect in background thread
	proto::Address dst = {
		.atype = IPV4,
		.ipv4 = { 127, 0, 0, 1 },
		.port = target_port,
	};
	ConnectArgs args = { .conn = &proxy_conn, .dst = dst };
	Thread t;
	t.create(&run_connect_thread, &args)!!;

	// 4. Target accepts outbound connection from proxy
	TcpSocket target_conn = tcp::accept(&target_server)!!;
	defer (void)target_conn.close();

	// 5. Client receives SOCKS5 success reply
	proto::Reply rep = proto::decode_reply((InStream)&client, tmem)!!;
	assert(rep.code == SUCCEEDED, "expected SUCCEEDED reply");
	assert(rep.bnd.atype == IPV4 || rep.bnd.atype == IPV6);
	assert(rep.bnd.port > 0, "expected non-zero bound port");

	// 6. Test bidirectional relay
	client.write("ping from client")!!;
	char[32] buf;
	sz n = target_conn.read(&buf)!!;
	assert((String)buf[:n] == "ping from client", "client -> target relay failed");

	target_conn.write("pong from target")!!;
	n = client.read(&buf)!!;
	assert((String)buf[:n] == "pong from target", "target -> client relay failed");

	// 7. Clean close
	client.close()!!;
	t.join()!!;
}

fn void test_connect_domain_success()
{
	acl::configure(true);
	defer acl::configure(false);

	TcpServerSocket target_server = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)target_server.close();
	ushort target_port = target_server.local_port()!!;

	TcpServerSocket proxy_server = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)proxy_server.close();
	ushort proxy_port = proxy_server.local_port()!!;

	TcpSocket client = tcp::connect("127.0.0.1", proxy_port)!!;
	defer (void)client.close();
	TcpSocket proxy_conn = tcp::accept(&proxy_server)!!;
	defer (void)proxy_conn.close();

	proto::Address dst = {
		.atype = DOMAIN,
		.domain = "127.0.0.1",
		.port = target_port,
	};
	ConnectArgs args = { .conn = &proxy_conn, .dst = dst };
	Thread t;
	t.create(&run_connect_thread, &args)!!;

	TcpSocket target_conn = tcp::accept(&target_server)!!;
	defer (void)target_conn.close();

	proto::Reply rep = proto::decode_reply((InStream)&client, tmem)!!;
	assert(rep.code == SUCCEEDED);

	client.write("domain ping")!!;
	char[32] buf;
	sz n = target_conn.read(&buf)!!;
	assert((String)buf[:n] == "domain ping");

	target_conn.write("domain pong")!!;
	n = client.read(&buf)!!;
	assert((String)buf[:n] == "domain pong");

	client.close()!!;
	t.join()!!;
}

fn void test_connect_connection_refused()
{
	acl::configure(true);
	defer acl::configure(false);

	TcpServerSocket temp_server = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	ushort dead_port = temp_server.local_port()!!;
	temp_server.close()!!;

	TcpServerSocket proxy_server = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)proxy_server.close();
	ushort proxy_port = proxy_server.local_port()!!;

	TcpSocket client = tcp::connect("127.0.0.1", proxy_port)!!;
	defer (void)client.close();
	TcpSocket proxy_conn = tcp::accept(&proxy_server)!!;
	defer (void)proxy_conn.close();

	proto::Address dst = {
		.atype = IPV4,
		.ipv4 = { 127, 0, 0, 1 },
		.port = dead_port,
	};
	handle_connect(&proxy_conn, dst);

	proto::Reply rep = proto::decode_reply((InStream)&client, tmem)!!;
	assert(rep.code == CONNECTION_REFUSED, "expected CONNECTION_REFUSED");
}

fn void test_connect_acl_denied_ipv4()
{
	acl::configure(false);

	TcpServerSocket proxy_server = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)proxy_server.close();
	ushort proxy_port = proxy_server.local_port()!!;

	TcpSocket client = tcp::connect("127.0.0.1", proxy_port)!!;
	defer (void)client.close();
	TcpSocket proxy_conn = tcp::accept(&proxy_server)!!;
	defer (void)proxy_conn.close();

	proto::Address dst = {
		.atype = IPV4,
		.ipv4 = { 127, 0, 0, 1 },
		.port = 8080,
	};
	handle_connect(&proxy_conn, dst);

	proto::Reply rep = proto::decode_reply((InStream)&client, tmem)!!;
	assert(rep.code == NOT_ALLOWED, "expected NOT_ALLOWED for loopback IPv4");
}

fn void test_connect_acl_denied_domain()
{
	acl::configure(false);

	TcpServerSocket proxy_server = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)proxy_server.close();
	ushort proxy_port = proxy_server.local_port()!!;

	TcpSocket client = tcp::connect("127.0.0.1", proxy_port)!!;
	defer (void)client.close();
	TcpSocket proxy_conn = tcp::accept(&proxy_server)!!;
	defer (void)proxy_conn.close();

	proto::Address dst = {
		.atype = DOMAIN,
		.domain = "127.0.0.1",
		.port = 8080,
	};
	handle_connect(&proxy_conn, dst);

	proto::Reply rep = proto::decode_reply((InStream)&client, tmem)!!;
	assert(rep.code == NOT_ALLOWED, "expected NOT_ALLOWED for domain resolving to loopback");
}


fn void test_bind_success_and_bidirectional_relay()
{
	// 1. Client-to-proxy connection pair
	TcpServerSocket proxy_server = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)proxy_server.close();
	ushort proxy_port = proxy_server.local_port()!!;

	TcpSocket client = tcp::connect("127.0.0.1", proxy_port)!!;
	defer (void)client.close();
	TcpSocket proxy_conn = tcp::accept(&proxy_server)!!;
	defer (void)proxy_conn.close();

	// 2. Start handle_bind in thread
	proto::Address dst = {
		.atype = IPV4,
		.ipv4 = { 127, 0, 0, 1 },
		.port = 0,
	};
	BindArgs args = { .conn = &proxy_conn, .dst = dst };
	Thread t;
	t.create(&run_bind_thread, &args)!!;

	// 3. Client reads first reply (listener's bound address/port)
	proto::Reply rep1 = proto::decode_reply((InStream)&client, tmem)!!;
	assert(rep1.code == SUCCEEDED, "expected first BIND reply to be SUCCEEDED");
	assert(rep1.bnd.port > 0, "expected non-zero listener port");

	// 4. External peer connects to proxy's listening port
	TcpSocket peer = tcp::connect("127.0.0.1", rep1.bnd.port)!!;
	defer (void)peer.close();

	// 5. Client reads second reply (peer's address/port)
	proto::Reply rep2 = proto::decode_reply((InStream)&client, tmem)!!;
	assert(rep2.code == SUCCEEDED, "expected second BIND reply to be SUCCEEDED");
	assert(rep2.bnd.port > 0, "expected non-zero peer port");

	// 6. Test bidirectional relay
	client.write("ping to peer")!!;
	char[32] buf;
	sz n = peer.read(&buf)!!;
	assert((String)buf[:n] == "ping to peer", "client -> peer relay failed");

	peer.write("pong to client")!!;
	n = client.read(&buf)!!;
	assert((String)buf[:n] == "pong to client", "peer -> client relay failed");

	// 7. Clean close
	client.close()!!;
	t.join()!!;
}

fn void test_bind_client_abort()
{
	TcpServerSocket proxy_server = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	defer (void)proxy_server.close();
	ushort proxy_port = proxy_server.local_port()!!;

	TcpSocket client = tcp::connect("127.0.0.1", proxy_port)!!;
	defer (void)client.close();
	TcpSocket proxy_conn = tcp::accept(&proxy_server)!!;
	defer (void)proxy_conn.close();

	proto::Address dst = {
		.atype = IPV4,
		.ipv4 = { 127, 0, 0, 1 },
		.port = 0,
	};
	BindArgs args = { .conn = &proxy_conn, .dst = dst };
	Thread t;
	t.create(&run_bind_thread, &args)!!;

	proto::Reply rep1 = proto::decode_reply((InStream)&client, tmem)!!;
	assert(rep1.code == SUCCEEDED);

	client.close()!!;
	t.join()!!;
}
