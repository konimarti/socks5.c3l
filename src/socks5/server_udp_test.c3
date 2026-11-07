module socks5::server;

import std::net, std::net::tcp, std::net::os, std::thread, std::io;
import socks5::proto;

struct AssociateArgs
{
	TcpSocket* conn;
	proto::Address client_hint;
}

fn int run_associate_thread(void* arg)
{
	@pool_init(mem, 65536)
	{
		AssociateArgs* args = (AssociateArgs*)arg;
		handle_udp_associate(args.conn, args.client_hint);
		return 0;
	};
}

module socks5::server @test;

import std::net, std::net::tcp, std::net::os, std::thread, std::io, std::time, libc;
import socks5::proto;

fn void test_udp_associate_forward_and_reply_and_teardown()
{
	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)listener.close();
	ushort proxy_tcp_port = listener.local_port()!!;

	TcpSocket client_tcp = tcp::connect("127.0.0.1", (int)proxy_tcp_port)!!;
	TcpSocket conn = tcp::accept(&listener)!!;

	proto::Address hint = { .atype = IPV4, .ipv4 = { 0, 0, 0, 0 }, .port = 0 };
	AssociateArgs args = { .conn = &conn, .client_hint = hint };
	Thread t;
	t.create(&run_associate_thread, &args)!!;

	// 1. Client reads SOCKS5 reply from TCP connection
	char[3] reply_head;
	io::read_all(&client_tcp, &reply_head)!!;
	assert(reply_head[0] == 0x05, "reply version");
	assert(reply_head[1] == 0x00, "reply succeeded");
	assert(reply_head[2] == 0x00, "reply reserved");

	proto::Address bnd = proto::decode_address(&client_tcp, tmem)!!;
	assert(bnd.atype == IPV4, "bound atype");
	assert(bnd.port > 0, "bound port non-zero");

	// 2. Setup loopback UDP target socket
	Socket target = bind_udp_socket("127.0.0.1", 0, os::AF_INET)!!;
	defer (void)target.close();
	ushort target_port = target.local_port()!!;

	// 3. Setup client UDP socket
	Socket client_udp = bind_udp_socket("127.0.0.1", 0, os::AF_INET)!!;
	defer (void)client_udp.close();

	// 4. Send datagram through proxy to target
	proto::Address target_dst = { .atype = IPV4, .ipv4 = { 127, 0, 0, 1 }, .port = target_port };
	char[] client_msg = "hello target from client";
	char[] req_packet = proto::encode_udp_header(tmem, target_dst, client_msg)!!;

	char[128] proxy_sa;
	Socklen_t proxy_sa_len = 0;
	bool ok = address_to_sockaddr(bnd, proxy_sa[0..], &proxy_sa_len);
	assert(ok, "convert bnd to sockaddr");

	sz sent = sendto(client_udp.sock, req_packet.ptr, req_packet.len, 0, (SockAddrPtr)&proxy_sa, proxy_sa_len);
	assert(sent == (sz)req_packet.len, "sent datagram to proxy");

	// 5. Target socket receives raw forwarded datagram
	char[256] target_recv_buf;
	char[128] from_proxy_sa;
	Socklen_t from_proxy_len = (Socklen_t)from_proxy_sa.len;
	sz got = recvfrom(target.sock, &target_recv_buf, target_recv_buf.len, 0, (SockAddrPtr)&from_proxy_sa, &from_proxy_len);
	assert(got == (sz)client_msg.len, "target received forwarded length");
	assert((String)target_recv_buf[:got] == (String)client_msg, "target received forwarded payload");

	// 6. Target socket replies back to proxy
	char[] target_reply = "hello client from target";
	sent = sendto(target.sock, target_reply.ptr, target_reply.len, 0, (SockAddrPtr)&from_proxy_sa, from_proxy_len);
	assert(sent == (sz)target_reply.len, "target sent reply");

	// 7. Client UDP socket receives SOCKS5-wrapped reply
	char[256] client_recv_buf;
	char[128] from_sa;
	Socklen_t from_len = (Socklen_t)from_sa.len;
	got = recvfrom(client_udp.sock, &client_recv_buf, client_recv_buf.len, 0, (SockAddrPtr)&from_sa, &from_len);
	assert(got > 0, "client received reply datagram");

	proto::UdpDatagram reply_dgram = proto::decode_udp_header(client_recv_buf[:got], tmem)!!;
	assert((String)reply_dgram.payload == (String)target_reply, "client received correct payload");
	assert(reply_dgram.dst.atype == IPV4, "reply dst atype is IPV4");
	assert(reply_dgram.dst.port == target_port, "reply dst port matches target");
	assert(reply_dgram.dst.ipv4 == { 127, 0, 0, 1 }, "reply dst ip matches target");

	// 8. Close TCP control connection -> verify proxy thread terminates promptly
	client_tcp.close()!!;
	t.join()!!;
	conn.close()!!;
}

fn void test_udp_associate_source_pinning_and_fragment_drop()
{
	TcpServerSocket listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)listener.close();
	ushort proxy_tcp_port = listener.local_port()!!;

	TcpSocket client_tcp = tcp::connect("127.0.0.1", (int)proxy_tcp_port)!!;
	TcpSocket conn = tcp::accept(&listener)!!;

	proto::Address hint = { .atype = IPV4, .ipv4 = { 0, 0, 0, 0 }, .port = 0 };
	AssociateArgs args = { .conn = &conn, .client_hint = hint };
	Thread t;
	t.create(&run_associate_thread, &args)!!;

	char[3] reply_head;
	io::read_all(&client_tcp, &reply_head)!!;
	proto::Address bnd = proto::decode_address(&client_tcp, tmem)!!;

	Socket target = bind_udp_socket("127.0.0.1", 0, os::AF_INET)!!;
	defer (void)target.close();
	(void)target.sock.set_non_blocking(true);
	ushort target_port = target.local_port()!!;

	Socket legit_client = bind_udp_socket("127.0.0.1", 0, os::AF_INET)!!;
	defer (void)legit_client.close();

	Socket attacker = bind_udp_socket("127.0.0.1", 0, os::AF_INET)!!;
	defer (void)attacker.close();

	char[128] proxy_sa;
	Socklen_t proxy_sa_len = 0;
	(void)address_to_sockaddr(bnd, proxy_sa[0..], &proxy_sa_len);

	// First datagram from legit client establishes pinning
	proto::Address target_dst = { .atype = IPV4, .ipv4 = { 127, 0, 0, 1 }, .port = target_port };
	char[] msg1 = "legit 1";
	char[] pkt1 = proto::encode_udp_header(tmem, target_dst, msg1)!!;
	(void)sendto(legit_client.sock, pkt1.ptr, pkt1.len, 0, (SockAddrPtr)&proxy_sa, proxy_sa_len);

	// Target receives legit 1
	Poll[1] tpolls = { { .socket = target.sock, .events = ANY_READ } };
	ulong n = net::poll(tpolls[0..], time::sec(1))!!;
	assert(n > 0, "target polled data from legit client");
	char[256] tbuf;
	sz got = recvfrom(target.sock, &tbuf, tbuf.len, 0, (SockAddrPtr)null, null);
	assert(got == (sz)msg1.len, "legit 1 length");

	// Attacker sends datagram to proxy -> proxy must silently discard
	char[] attack_msg = "attacker payload";
	char[] attack_pkt = proto::encode_udp_header(tmem, target_dst, attack_msg)!!;
	(void)sendto(attacker.sock, attack_pkt.ptr, attack_pkt.len, 0, (SockAddrPtr)&proxy_sa, proxy_sa_len);

	// Poll target with short timeout: must timeout (nothing received)
	n = net::poll(tpolls[0..], time::ms(100))!!;
	assert(n == 0, "target must not receive attacker datagram");

	// Send fragmented datagram (FRAG != 0) from legit client -> proxy must silently drop
	char[] frag_msg = "fragmented payload";
	char[] frag_pkt = proto::encode_udp_header(tmem, target_dst, frag_msg)!!;
	frag_pkt[2] = 1; // set FRAG = 1
	(void)sendto(legit_client.sock, frag_pkt.ptr, frag_pkt.len, 0, (SockAddrPtr)&proxy_sa, proxy_sa_len);

	// Poll target with short timeout: must timeout (nothing received)
	n = net::poll(tpolls[0..], time::ms(100))!!;
	assert(n == 0, "target must not receive fragmented datagram");

	// Teardown
	client_tcp.close()!!;
	t.join()!!;
	conn.close()!!;
}
