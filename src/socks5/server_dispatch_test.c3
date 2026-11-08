// Covers negotiate_and_serve's handling of a malformed/unsupported
// request: RFC 1928 section 6 defines COMMAND_NOT_SUPPORTED (0x07) and
// ADDRESS_TYPE_NOT_SUPPORTED (0x08) replies for exactly this case, and an
// earlier version of this code silently dropped the connection instead
// (found by an independent red-team review, reviews/server-review-v1.md).
module socks5::server;

import std::net, std::net::tcp, std::thread;

struct DispatchArgs
{
	Socks5Server* server;
	TcpSocket conn;
}

fn int run_handle_connection(void* arg)
{
	DispatchArgs* a = (DispatchArgs*)arg;
	handle_connection(a.server, &a.conn);
	(void)a.conn.close();
	return 0;
}

module socks5::server @test;

import std::net, std::net::tcp, std::thread, std::io;
import socks5::proto;

fn void test_unsupported_command_replies_with_correct_code()
{
	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)listener.close();
	ushort port = listener.local_port()!!;
	TcpSocket client = tcp::connect("127.0.0.1", port)!!;
	defer (void)client.close();
	TcpSocket conn = tcp::accept(&listener)!!;

	Socks5Server server;
	server.allow_no_auth = true;
	DispatchArgs args = { .server = &server, .conn = conn };
	Thread t;
	t.create(&run_handle_connection, &args)!!;

	char[] greeting = { proto::VERSION, 1, Socks5Method.NO_AUTH.wire };
	client.write(greeting)!!;
	char[2] method_sel;
	io::read_all(&client, &method_sel)!!;
	assert(method_sel[1] == Socks5Method.NO_AUTH.wire);

	// CMD = 0x09: not CONNECT/BIND/UDP_ASSOCIATE.
	char[] req = { proto::VERSION, 0x09, 0, (char)Socks5AddressType.IPV4.wire, 127, 0, 0, 1, 0, 80 };
	client.write(req)!!;

	char[3] reply_head;
	io::read_all(&client, &reply_head)!!;
	assert(reply_head[0] == proto::VERSION);
	assert(reply_head[1] == Socks5ReplyCode.COMMAND_NOT_SUPPORTED.wire);
	assert(reply_head[2] == 0);

	t.join()!!;
}

fn void test_unsupported_address_type_replies_with_correct_code()
{
	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)listener.close();
	ushort port = listener.local_port()!!;
	TcpSocket client = tcp::connect("127.0.0.1", port)!!;
	defer (void)client.close();
	TcpSocket conn = tcp::accept(&listener)!!;

	Socks5Server server;
	server.allow_no_auth = true;
	DispatchArgs args = { .server = &server, .conn = conn };
	Thread t;
	t.create(&run_handle_connection, &args)!!;

	char[] greeting = { proto::VERSION, 1, Socks5Method.NO_AUTH.wire };
	client.write(greeting)!!;
	char[2] method_sel;
	io::read_all(&client, &method_sel)!!;

	// ATYP = 0x02 is GSSAPI's method id, not a valid address type.
	char[] req = { proto::VERSION, Socks5Command.CONNECT.wire, 0, 0x02 };
	client.write(req)!!;

	char[3] reply_head;
	io::read_all(&client, &reply_head)!!;
	assert(reply_head[0] == proto::VERSION);
	assert(reply_head[1] == Socks5ReplyCode.ADDRESS_TYPE_NOT_SUPPORTED.wire);
	assert(reply_head[2] == 0);

	t.join()!!;
}
