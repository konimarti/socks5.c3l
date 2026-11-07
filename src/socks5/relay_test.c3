module socks5::relay_test;

import std::net, std::net::tcp, std::thread, std::io, socks5::relay;

struct RelayArgs
{
	Socket* a;
	Socket* b;
}

fn int run_relay(void* arg)
{
	RelayArgs* args = (RelayArgs*)arg;
	relay::relay_bidirectional(args.a, args.b);
	return 0;
}

module socks5::relay_test @test;

import std::net, std::net::tcp, std::thread, std::io;

fn void test_relay_both_directions_and_eof()
{
	TcpServerSocket server_a = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)server_a.close();
	ushort port_a = server_a.local_port()!!;
	TcpSocket client_a = tcp::connect("127.0.0.1", port_a)!!;
	TcpSocket conn_a = tcp::accept(&server_a)!!;

	TcpServerSocket server_b = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)server_b.close();
	ushort port_b = server_b.local_port()!!;
	TcpSocket client_b = tcp::connect("127.0.0.1", port_b)!!;
	TcpSocket conn_b = tcp::accept(&server_b)!!;

	RelayArgs args = { .a = (Socket*)&conn_a, .b = (Socket*)&conn_b };
	Thread t;
	t.create(&run_relay, &args)!!;

	client_a.write("ping")!!;
	char[16] buf;
	sz n = client_b.read(&buf)!!;
	assert((String)buf[:n] == "ping", "a->b relay failed");

	client_b.write("pong")!!;
	n = client_a.read(&buf)!!;
	assert((String)buf[:n] == "pong", "b->a relay failed");

	client_a.close()!!;
	t.join()!!;

	client_b.close()!!;
	conn_a.close()!!;
	conn_b.close()!!;
}
