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
	assert(methods[0] == Socks5Method.NO_AUTH.wire);
	assert(methods[1] == Socks5Method.USERNAME_PASSWORD.wire);
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
	Socks5UserpassRequest req = decode_userpass_request(&r, tmem)!!;
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
	Socks5Address addr = { .atype = IPV4, .ipv4 = { 192, 168, 1, 1 }, .port = 1080 };
	ByteWriter w;
	w.init(tmem);
	encode_address(&w, addr)!!;

	ByteReader r;
	r.init(w.array_view());
	Socks5Address back = decode_address(&r, tmem)!!;
	assert(back.atype == IPV4);
	assert(back.ipv4[0] == 192 && back.ipv4[3] == 1);
	assert(back.port == 1080);
}

fn void test_address_round_trip_ipv6()
{
	Socks5Address addr = { .atype = IPV6, .port = 443 };
	addr.ipv6[15] = 1;
	ByteWriter w;
	w.init(tmem);
	encode_address(&w, addr)!!;

	ByteReader r;
	r.init(w.array_view());
	Socks5Address back = decode_address(&r, tmem)!!;
	assert(back.atype == IPV6);
	assert(back.ipv6[15] == 1);
	assert(back.port == 443);
}

fn void test_address_round_trip_domain()
{
	Socks5Address addr = { .atype = DOMAIN, .domain = "example.com", .port = 80 };
	ByteWriter w;
	w.init(tmem);
	encode_address(&w, addr)!!;

	ByteReader r;
	r.init(w.array_view());
	Socks5Address back = decode_address(&r, tmem)!!;
	assert(back.atype == DOMAIN);
	assert(back.domain == "example.com");
	assert(back.port == 80);
}

fn void test_address_domain_max_length()
{
	char[255] name;
	for (usz i = 0; i < name.len; i++) name[i] = 'a';
	Socks5Address addr = { .atype = DOMAIN, .domain = (String)&name, .port = 1 };
	ByteWriter w;
	w.init(tmem);
	encode_address(&w, addr)!!;

	ByteReader r;
	r.init(w.array_view());
	Socks5Address back = decode_address(&r, tmem)!!;
	assert(back.domain.len == 255);
}

fn void test_encode_address_empty_domain_rejected()
{
	Socks5Address addr = { .atype = DOMAIN, .domain = "", .port = 1 };
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
	char[] raw = { (char)Socks5AddressType.DOMAIN.wire, 0, 0, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_address(&r, tmem), NAME_TOO_LONG);
}

fn void test_request_round_trip_connect()
{
	Socks5Address dst = { .atype = DOMAIN, .domain = "example.com", .port = 443 };
	ByteWriter w;
	w.init(tmem);
	w.write_byte(VERSION)!!;
	w.write_byte(Socks5Command.CONNECT.wire)!!;
	w.write_byte(0)!!; // RSV
	encode_address(&w, dst)!!;

	ByteReader r;
	r.init(w.array_view());
	Socks5Request req = decode_request(&r, tmem)!!;
	assert(req.cmd == CONNECT);
	assert(req.dst.domain == "example.com");
	assert(req.dst.port == 443);
}

fn void test_request_bad_version()
{
	char[] raw = { 0x04, Socks5Command.CONNECT.wire, 0, (char)Socks5AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_request(&r, tmem), UNSUPPORTED_VERSION);
}

fn void test_request_unsupported_command()
{
	char[] raw = { VERSION, 0x7f, 0, (char)Socks5AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_request(&r, tmem), UNSUPPORTED_COMMAND);
}

fn void test_request_bad_reserved_byte()
{
	char[] raw = { VERSION, Socks5Command.CONNECT.wire, 0x01, (char)Socks5AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_request(&r, tmem), MALFORMED_MESSAGE);
}

fn void test_encode_reply()
{
	Socks5Address bnd = { .atype = IPV4, .ipv4 = { 10, 0, 0, 1 }, .port = 1080 };
	ByteWriter w;
	w.init(tmem);
	encode_reply(&w, Socks5ReplyCode.SUCCEEDED, bnd)!!;
	char[] got = w.array_view();
	assert(got[0] == VERSION);
	assert(got[1] == Socks5ReplyCode.SUCCEEDED.wire);
	assert(got[2] == 0);
}

fn void test_udp_header_round_trip()
{
	Socks5Address dst = { .atype = IPV4, .ipv4 = { 8, 8, 8, 8 }, .port = 53 };
	char[] payload = "dns-query";
	char[] packet = encode_udp_header(tmem, dst, payload)!!;

	Socks5UdpDatagram dgram = decode_udp_header(packet, tmem)!!;
	assert(dgram.dst.atype == IPV4);
	assert(dgram.dst.port == 53);
	assert((String)dgram.payload == "dns-query");
}

fn void test_udp_header_bad_reserved()
{
	char[] raw = { 0x01, 0x00, 0x00, (char)Socks5AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	@expect_fault(decode_udp_header(raw, tmem), MALFORMED_MESSAGE);
}

fn void test_udp_header_fragmentation_unsupported()
{
	char[] raw = { 0x00, 0x00, 0x01, (char)Socks5AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	@expect_fault(decode_udp_header(raw, tmem), UNSUPPORTED_FRAGMENTATION);
}

// --- client-side additions: encode_greeting / decode_method_selection ---

fn void test_encode_greeting()
{
	ByteWriter w;
	w.init(tmem);
	Socks5Method[2] methods = { NO_AUTH, USERNAME_PASSWORD };
	encode_greeting(&w, methods[0..])!!;
	char[] got = w.array_view();
	assert(got.len == 4);
	assert(got[0] == VERSION);
	assert(got[1] == 2);
	assert(got[2] == Socks5Method.NO_AUTH.wire);
	assert(got[3] == Socks5Method.USERNAME_PASSWORD.wire);
}

fn void test_encode_greeting_empty_rejected()
{
	ByteWriter w;
	w.init(tmem);
	Socks5Method[1] one = { GSSAPI };
	@expect_fault(encode_greeting(&w, one[:0]), NAME_TOO_LONG);
}

fn void test_encode_greeting_too_many_rejected()
{
	ByteWriter w;
	w.init(tmem);
	Socks5Method[256] many;
	@expect_fault(encode_greeting(&w, many[0..]), NAME_TOO_LONG);
}

fn void test_greeting_round_trip()
{
	ByteWriter w;
	w.init(tmem);
	Socks5Method[3] methods = { NO_AUTH, GSSAPI, USERNAME_PASSWORD };
	encode_greeting(&w, methods[0..])!!;

	ByteReader r;
	r.init(w.array_view());
	char[] got = decode_greeting(&r, tmem)!!;
	assert(got.len == 3);
	assert(methods_contains(got, NO_AUTH));
	assert(methods_contains(got, GSSAPI));
	assert(methods_contains(got, USERNAME_PASSWORD));
}

fn void test_decode_method_selection_ok()
{
	char[] raw = { VERSION, Socks5Method.USERNAME_PASSWORD.wire };
	ByteReader r;
	r.init(raw);
	Socks5Method m = decode_method_selection(&r)!!;
	assert(m == USERNAME_PASSWORD);
}

fn void test_decode_method_selection_no_acceptable()
{
	char[] raw = { VERSION, Socks5Method.NO_ACCEPTABLE.wire };
	ByteReader r;
	r.init(raw);
	assert(decode_method_selection(&r)!! == NO_ACCEPTABLE);
}

fn void test_decode_method_selection_bad_version()
{
	char[] raw = { 0x04, 0x00 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_method_selection(&r), UNSUPPORTED_VERSION);
}

fn void test_decode_method_selection_unknown_method()
{
	char[] raw = { VERSION, 0x7f };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_method_selection(&r), MALFORMED_MESSAGE);
}

fn void test_method_selection_round_trip()
{
	ByteWriter w;
	w.init(tmem);
	encode_method_selection(&w, NO_AUTH)!!;
	ByteReader r;
	r.init(w.array_view());
	assert(decode_method_selection(&r)!! == NO_AUTH);
}

// --- client-side additions: encode_userpass_request / decode_userpass_reply ---

fn void test_userpass_request_round_trip()
{
	ByteWriter w;
	w.init(tmem);
	encode_userpass_request(&w, "alice", "secret")!!;

	ByteReader r;
	r.init(w.array_view());
	Socks5UserpassRequest req = decode_userpass_request(&r, tmem)!!;
	assert(req.username == "alice");
	assert(req.password == "secret");
}

fn void test_encode_userpass_request_empty_rejected()
{
	ByteWriter w;
	w.init(tmem);
	@expect_fault(encode_userpass_request(&w, "", "x"), NAME_TOO_LONG);
	@expect_fault(encode_userpass_request(&w, "x", ""), NAME_TOO_LONG);
}

fn void test_encode_userpass_request_too_long_rejected()
{
	ByteWriter w;
	w.init(tmem);
	char[256] big;
	String s = (String)&big;
	@expect_fault(encode_userpass_request(&w, s, "x"), NAME_TOO_LONG);
	@expect_fault(encode_userpass_request(&w, "x", s), NAME_TOO_LONG);
}

fn void test_decode_userpass_reply_ok_and_fail()
{
	char[] raw_ok = { AUTH_VERSION, 0x00 };
	ByteReader r;
	r.init(raw_ok);
	assert(decode_userpass_reply(&r)!!);

	char[] raw_bad = { AUTH_VERSION, 0x01 };
	r.init(raw_bad);
	assert(!decode_userpass_reply(&r)!!);
}

fn void test_decode_userpass_reply_bad_version()
{
	char[] raw = { VERSION, 0x00 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_userpass_reply(&r), UNSUPPORTED_VERSION);
}

fn void test_userpass_reply_round_trip()
{
	ByteWriter w;
	w.init(tmem);
	encode_userpass_reply(&w, true)!!;
	ByteReader r;
	r.init(w.array_view());
	assert(decode_userpass_reply(&r)!!);
}

// --- client-side additions: encode_request / decode_reply ---

fn void test_request_encode_round_trip_ipv4()
{
	Socks5Address dst = { .atype = IPV4, .ipv4 = { 1, 2, 3, 4 }, .port = 8080 };
	ByteWriter w;
	w.init(tmem);
	encode_request(&w, Socks5Command.CONNECT, dst)!!;

	ByteReader r;
	r.init(w.array_view());
	Socks5Request req = decode_request(&r, tmem)!!;
	assert(req.cmd == CONNECT);
	assert(req.dst.atype == IPV4);
	assert(req.dst.ipv4[0] == 1 && req.dst.ipv4[3] == 4);
	assert(req.dst.port == 8080);
}

fn void test_request_encode_round_trip_domain_bind()
{
	Socks5Address dst = { .atype = DOMAIN, .domain = "example.org", .port = 1080 };
	ByteWriter w;
	w.init(tmem);
	encode_request(&w, Socks5Command.BIND, dst)!!;

	ByteReader r;
	r.init(w.array_view());
	Socks5Request req = decode_request(&r, tmem)!!;
	assert(req.cmd == BIND);
	assert(req.dst.atype == DOMAIN);
	assert(req.dst.domain == "example.org");
	assert(req.dst.port == 1080);
}

fn void test_reply_round_trip()
{
	Socks5Address bnd = { .atype = DOMAIN, .domain = "proxy.example", .port = 1080 };
	ByteWriter w;
	w.init(tmem);
	encode_reply(&w, Socks5ReplyCode.SUCCEEDED, bnd)!!;

	ByteReader r;
	r.init(w.array_view());
	Socks5Reply rep = decode_reply(&r, tmem)!!;
	assert(rep.code == SUCCEEDED);
	assert(rep.bnd.atype == DOMAIN);
	assert(rep.bnd.domain == "proxy.example");
	assert(rep.bnd.port == 1080);
}

fn void test_reply_round_trip_error_code()
{
	Socks5Address bnd = { .atype = IPV4, .ipv4 = { 0, 0, 0, 0 }, .port = 0 };
	ByteWriter w;
	w.init(tmem);
	encode_reply(&w, Socks5ReplyCode.CONNECTION_REFUSED, bnd)!!;

	ByteReader r;
	r.init(w.array_view());
	Socks5Reply rep = decode_reply(&r, tmem)!!;
	assert(rep.code == CONNECTION_REFUSED);
	assert(rep.bnd.atype == IPV4);
	assert(rep.bnd.port == 0);
}

fn void test_decode_reply_bad_version()
{
	char[] raw = { 0x04, 0x00, 0x00, (char)Socks5AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_reply(&r, tmem), UNSUPPORTED_VERSION);
}

fn void test_decode_reply_bad_reserved_byte()
{
	char[] raw = { VERSION, 0x00, 0x01, (char)Socks5AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_reply(&r, tmem), MALFORMED_MESSAGE);
}

fn void test_decode_reply_unknown_code()
{
	char[] raw = { VERSION, 0x7f, 0x00, (char)Socks5AddressType.IPV4.wire, 0, 0, 0, 0, 0, 0 };
	ByteReader r;
	r.init(raw);
	@expect_fault(decode_reply(&r, tmem), MALFORMED_MESSAGE);
}

// --- full client<->server handshake over one byte stream ---

fn void test_full_handshake_wire_round_trip()
{
	ByteWriter w;
	w.init(tmem);

	// client: greeting, userpass request, CONNECT request
	Socks5Method[2] methods = { NO_AUTH, USERNAME_PASSWORD };
	encode_greeting(&w, methods[0..])!!;
	encode_userpass_request(&w, "bob", "hunter2")!!;
	Socks5Address dst = { .atype = DOMAIN, .domain = "example.com", .port = 443 };
	encode_request(&w, Socks5Command.CONNECT, dst)!!;

	// server: method selection, userpass reply, CONNECT reply
	ByteWriter sw;
	sw.init(tmem);
	encode_method_selection(&sw, USERNAME_PASSWORD)!!;
	encode_userpass_reply(&sw, true)!!;
	Socks5Address bnd = { .atype = IPV4, .ipv4 = { 10, 0, 0, 1 }, .port = 40000 };
	encode_reply(&sw, Socks5ReplyCode.SUCCEEDED, bnd)!!;

	// play both directions through one reader each
	ByteReader cr;
	cr.init(w.array_view());
	char[] got_methods = decode_greeting(&cr, tmem)!!;
	assert(got_methods.len == 2);
	Socks5UserpassRequest ureq = decode_userpass_request(&cr, tmem)!!;
	assert(ureq.username == "bob" && ureq.password == "hunter2");
	Socks5Request req = decode_request(&cr, tmem)!!;
	assert(req.cmd == CONNECT);
	assert(req.dst.domain == "example.com" && req.dst.port == 443);

	ByteReader sr;
	sr.init(sw.array_view());
	assert(decode_method_selection(&sr)!! == USERNAME_PASSWORD);
	assert(decode_userpass_reply(&sr)!!);
	Socks5Reply rep = decode_reply(&sr, tmem)!!;
	assert(rep.code == SUCCEEDED);
	assert(rep.bnd.ipv4[0] == 10 && rep.bnd.port == 40000);
}
