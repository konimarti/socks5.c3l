module socks5::proto @test;

import std::io;

macro void @expect_fault(#expr, fault want)
{
	if (catch err = #expr)
	{
		assert(err == want, "got %s, wanted %s", err, want);
		return;
	}
	assert(false, "expected fault %s but call succeeded", want);
}

fn void test_decode_greeting_ok()
{
	char[] raw = { VERSION, 2, 0x00, 0x02 };
	ByteReader r;
	r.init(raw);
	char[] methods = decode_greeting(&r, tmem)!!;
	assert(methods.len == 2);
	assert(methods[0] == Method.NO_AUTH.wire);
	assert(methods[1] == Method.USERNAME_PASSWORD.wire);
	assert(methods_contains(methods, NO_AUTH));
	assert(methods_contains(methods, USERNAME_PASSWORD));
	assert(!methods_contains(methods, GSSAPI));
}

fn void test_decode_greeting_bad_version()
{
	char[] raw = { 0x04, 1, 0x00 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_greeting(&r, tmem), UNSUPPORTED_VERSION);
}

fn void test_decode_greeting_zero_methods()
{
	char[] raw = { VERSION, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_greeting(&r, tmem), NAME_TOO_LONG);
}

fn void test_decode_greeting_truncated()
{
	char[] raw = { VERSION, 2, 0x00 }; // claims 2 methods, only 1 present
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_greeting(&r, tmem), io::UNEXPECTED_EOF);
}

fn void test_encode_method_selection()
{
	ByteWriter w;
	w.init(tmem);
	encode_method_selection(&w, USERNAME_PASSWORD)!!;
	char[] got = w.array_view();
	assert(got.len == 2);
	assert(got[0] == VERSION);
	assert(got[1] == 0x02);
}

fn void test_userpass_round_trip()
{
	ByteWriter w;
	w.init(tmem);
	char[] raw = { AUTH_VERSION, 3, 'b', 'o', 'b', 4, 'p', 'a', 's', 's' };
	ByteReader r;
	r.init(raw);
	UserpassRequest req = decode_userpass_request(&r, tmem)!!;
	assert(req.username == "bob");
	assert(req.password == "pass");

	encode_userpass_reply(&w, true)!!;
	char[] got = w.array_view();
	assert(got[0] == AUTH_VERSION && got[1] == 0);
}

fn void test_userpass_bad_version()
{
	char[] raw = { 0x05, 1, 'x' };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_userpass_request(&r, tmem), UNSUPPORTED_VERSION);
}

fn void test_address_round_trip_ipv4()
{
	Address addr = { .atype = IPV4, .ipv4 = { 192, 168, 1, 1 }, .port = 1080 };
	ByteWriter w;
	w.init(tmem);
	encode_address(&w, addr)!!;

	ByteReader r;
	r.init(w.array_view());
	Address back = decode_address(&r, tmem)!!;
	assert(back.atype == IPV4);
	assert(back.ipv4[0] == 192 && back.ipv4[3] == 1);
	assert(back.port == 1080);
}

fn void test_address_round_trip_ipv6()
{
	Address addr = { .atype = IPV6, .port = 443 };
	addr.ipv6[15] = 1;
	ByteWriter w;
	w.init(tmem);
	encode_address(&w, addr)!!;

	ByteReader r;
	r.init(w.array_view());
	Address back = decode_address(&r, tmem)!!;
	assert(back.atype == IPV6);
	assert(back.ipv6[15] == 1);
	assert(back.port == 443);
}

fn void test_address_round_trip_domain()
{
	Address addr = { .atype = DOMAIN, .domain = "example.com", .port = 80 };
	ByteWriter w;
	w.init(tmem);
	encode_address(&w, addr)!!;

	ByteReader r;
	r.init(w.array_view());
	Address back = decode_address(&r, tmem)!!;
	assert(back.atype == DOMAIN);
	assert(back.domain == "example.com");
	assert(back.port == 80);
}

fn void test_address_domain_max_length()
{
	char[255] name;
	for (usz i = 0; i < name.len; i++) name[i] = 'a';
	Address addr = { .atype = DOMAIN, .domain = (String)&name, .port = 1 };
	ByteWriter w;
	w.init(tmem);
	encode_address(&w, addr)!!;

	ByteReader r;
	r.init(w.array_view());
	Address back = decode_address(&r, tmem)!!;
	assert(back.domain.len == 255);
}

fn void test_encode_address_empty_domain_rejected()
{
	Address addr = { .atype = DOMAIN, .domain = "", .port = 1 };
	ByteWriter w;
	w.init(tmem);
	@expect_fault(encode_address(&w, addr), NAME_TOO_LONG);
}

fn void test_decode_address_unsupported_type()
{
	char[] raw = { 0x02, 0, 0 }; // 0x02 is not a valid ATYP (GSSAPI's method id, not an address type)
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_address(&r, tmem), UNSUPPORTED_ADDRESS_TYPE);
}

fn void test_decode_address_domain_zero_length()
{
	char[] raw = { (char)AddressType.DOMAIN.wire, 0, 0, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_address(&r, tmem), NAME_TOO_LONG);
}

fn void test_request_round_trip_connect()
{
	Address dst = { .atype = DOMAIN, .domain = "example.com", .port = 443 };
	ByteWriter w;
	w.init(tmem);
	w.write_byte(VERSION)!!;
	w.write_byte(Command.CONNECT.wire)!!;
	w.write_byte(0)!!; // RSV
	encode_address(&w, dst)!!;

	ByteReader r;
	r.init(w.array_view());
	Request req = decode_request(&r, tmem)!!;
	assert(req.cmd == CONNECT);
	assert(req.dst.domain == "example.com");
	assert(req.dst.port == 443);
}

fn void test_request_bad_version()
{
	char[] raw = { 0x04, Command.CONNECT.wire, 0, (char)AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_request(&r, tmem), UNSUPPORTED_VERSION);
}

fn void test_request_unsupported_command()
{
	char[] raw = { VERSION, 0x7f, 0, (char)AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_request(&r, tmem), UNSUPPORTED_COMMAND);
}

fn void test_request_bad_reserved_byte()
{
	char[] raw = { VERSION, Command.CONNECT.wire, 0x01, (char)AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_request(&r, tmem), MALFORMED_MESSAGE);
}

fn void test_encode_reply()
{
	Address bnd = { .atype = IPV4, .ipv4 = { 10, 0, 0, 1 }, .port = 1080 };
	ByteWriter w;
	w.init(tmem);
	encode_reply(&w, ReplyCode.SUCCEEDED, bnd)!!;
	char[] got = w.array_view();
	assert(got[0] == VERSION);
	assert(got[1] == ReplyCode.SUCCEEDED.wire);
	assert(got[2] == 0);
}

fn void test_udp_header_round_trip()
{
	Address dst = { .atype = IPV4, .ipv4 = { 8, 8, 8, 8 }, .port = 53 };
	char[] payload = "dns-query";
	char[] packet = encode_udp_header(tmem, dst, payload)!!;

	UdpDatagram dgram = decode_udp_header(packet, tmem)!!;
	assert(dgram.dst.atype == IPV4);
	assert(dgram.dst.port == 53);
	assert((String)dgram.payload == "dns-query");
}

fn void test_udp_header_bad_reserved()
{
	char[] raw = { 0x01, 0x00, 0x00, (char)AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	@expect_fault(decode_udp_header(raw, tmem), MALFORMED_MESSAGE);
}

fn void test_udp_header_fragmentation_unsupported()
{
	char[] raw = { 0x00, 0x00, 0x01, (char)AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	@expect_fault(decode_udp_header(raw, tmem), UNSUPPORTED_FRAGMENTATION);
}
