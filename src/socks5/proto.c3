// SOCKS5 wire format (RFC 1928 + RFC 1929 username/password subnegotiation).
// Pure encode/decode over InStream/OutStream: no sockets, no allocation beyond
// what a decoded value needs to outlive the call (domain names, credentials).
module socks5::proto;

import std::io;

const char VERSION = 0x05;
const char AUTH_VERSION = 0x01;
const usz MAX_NAME_LEN = 255; // ULEN/PLEN/domain-len are one byte: 1..255

enum Method : char (char wire)
{
	NO_AUTH            { 0x00 },
	GSSAPI             { 0x01 },
	USERNAME_PASSWORD  { 0x02 },
	NO_ACCEPTABLE      { 0xff },
}

enum Command : char (char wire)
{
	CONNECT       { 0x01 },
	BIND          { 0x02 },
	UDP_ASSOCIATE { 0x03 },
}

enum AddressType : char (char wire)
{
	IPV4   { 0x01 },
	DOMAIN { 0x03 },
	IPV6   { 0x04 },
}

enum ReplyCode : char (char wire)
{
	SUCCEEDED                  { 0x00 },
	GENERAL_FAILURE            { 0x01 },
	NOT_ALLOWED                { 0x02 },
	NETWORK_UNREACHABLE        { 0x03 },
	HOST_UNREACHABLE           { 0x04 },
	CONNECTION_REFUSED         { 0x05 },
	TTL_EXPIRED                { 0x06 },
	COMMAND_NOT_SUPPORTED      { 0x07 },
	ADDRESS_TYPE_NOT_SUPPORTED { 0x08 },
}

excuse
{
	UNSUPPORTED_VERSION,
	UNSUPPORTED_ADDRESS_TYPE,
	UNSUPPORTED_COMMAND,
	UNSUPPORTED_FRAGMENTATION, // FRAG != 0: no UDP reassembly support (v1 limitation)
	MALFORMED_MESSAGE,
	NAME_TOO_LONG,
}

fn Command? command_from_wire(char w)
{
	switch (w)
	{
		case 0x01: return CONNECT;
		case 0x02: return BIND;
		case 0x03: return UDP_ASSOCIATE;
		default: return UNSUPPORTED_COMMAND~;
	}
}

fn AddressType? address_type_from_wire(char w)
{
	switch (w)
	{
		case 0x01: return IPV4;
		case 0x03: return DOMAIN;
		case 0x04: return IPV6;
		default: return UNSUPPORTED_ADDRESS_TYPE~;
	}
}

fn Method? method_from_wire(char w)
{
	switch (w)
	{
		case 0x00: return NO_AUTH;
		case 0x01: return GSSAPI;
		case 0x02: return USERNAME_PASSWORD;
		case 0xff: return NO_ACCEPTABLE;
		default: return MALFORMED_MESSAGE~;
	}
}

fn ReplyCode? reply_code_from_wire(char w)
{
	switch (w)
	{
		case 0x00: return SUCCEEDED;
		case 0x01: return GENERAL_FAILURE;
		case 0x02: return NOT_ALLOWED;
		case 0x03: return NETWORK_UNREACHABLE;
		case 0x04: return HOST_UNREACHABLE;
		case 0x05: return CONNECTION_REFUSED;
		case 0x06: return TTL_EXPIRED;
		case 0x07: return COMMAND_NOT_SUPPORTED;
		case 0x08: return ADDRESS_TYPE_NOT_SUPPORTED;
		default: return MALFORMED_MESSAGE~;
	}
}

struct Address
{
	AddressType atype;
	char[4] ipv4;
	char[16] ipv6;
	String domain; // set only when atype == DOMAIN; allocated by the decoder's caller
	ushort port;   // host byte order
}

struct Request
{
	Command cmd;
	Address dst;
}

struct Reply
{
	ReplyCode code;
	Address bnd;
}

struct UserpassRequest
{
	String username;
	String password;
}

struct UdpDatagram
{
	Address dst;
	char[] payload; // view into the caller's buffer; not copied, not owned
}

// --- greeting / method selection (RFC 1928 section 3) ---

<*
 Encode the client's version-identifier/method-selection message.
 @return? NAME_TOO_LONG : "methods.len == 0 or > 255"
*>
fn void? encode_greeting(OutStream out, Method[] methods)
{
	if (methods.len == 0 || methods.len > MAX_NAME_LEN) return NAME_TOO_LONG~;
	out.write_byte(VERSION)!;
	out.write_byte((char)methods.len)!;
	foreach (Method m : methods) out.write_byte(m.wire)!;
}

<*
 Decode the client's version-identifier/method-selection message.
 @return "the raw METHODS list, allocated with `allocator`"
 @return? UNSUPPORTED_VERSION
 @return? NAME_TOO_LONG : "NMETHODS == 0"
*>
fn char[]? decode_greeting(InStream in, Allocator allocator)
{
	char ver = in.read_byte()!;
	if (ver != VERSION) return UNSUPPORTED_VERSION~;
	char nmethods = in.read_byte()!;
	if (nmethods == 0) return NAME_TOO_LONG~;
	char[] methods = alloc::alloc_array(allocator, char, nmethods)[:nmethods];
	io::read_all(in, methods)!;
	return methods;
}

fn bool methods_contains(char[] methods, Method m)
{
	foreach (char c : methods) if (c == m.wire) return true;
	return false;
}

fn void? encode_method_selection(OutStream out, Method selected)
{
	char[2] msg = { VERSION, selected.wire };
	io::write_all(out, &msg)!;
}

<*
 Decode the server's method-selection message.
 @return? UNSUPPORTED_VERSION
 @return? MALFORMED_MESSAGE : "selected method byte is not a known method"
*>
fn Method? decode_method_selection(InStream in)
{
	char ver = in.read_byte()!;
	if (ver != VERSION) return UNSUPPORTED_VERSION~;
	char raw = in.read_byte()!;
	return method_from_wire(raw);
}

// --- username/password subnegotiation (RFC 1929) ---

<*
 @return? UNSUPPORTED_VERSION
 @return? NAME_TOO_LONG : "ULEN or PLEN was 0"
*>
fn UserpassRequest? decode_userpass_request(InStream in, Allocator allocator)
{
	char ver = in.read_byte()!;
	if (ver != AUTH_VERSION) return UNSUPPORTED_VERSION~;
	char ulen = in.read_byte()!;
	if (ulen == 0) return NAME_TOO_LONG~; // RFC 1929 2: ULEN is 1..255
	char[] uname = alloc::alloc_array(allocator, char, ulen)[:ulen];
	io::read_all(in, uname)!;
	char plen = in.read_byte()!;
	if (plen == 0) return NAME_TOO_LONG~; // RFC 1929 2: PLEN is 1..255
	char[] passwd = alloc::alloc_array(allocator, char, plen)[:plen];
	io::read_all(in, passwd)!;
	return { .username = (String)uname, .password = (String)passwd };
}

fn void? encode_userpass_reply(OutStream out, bool ok)
{
	char[2] msg = { AUTH_VERSION, ok ? 0 : 1 };
	io::write_all(out, &msg)!;
}

<*
 Encode the client's username/password request (RFC 1929 section 2).
 @return? NAME_TOO_LONG : "user or pass length outside 1..255"
*>
fn void? encode_userpass_request(OutStream out, String user, String pass)
{
	if (user.len == 0 || user.len > MAX_NAME_LEN) return NAME_TOO_LONG~;
	if (pass.len == 0 || pass.len > MAX_NAME_LEN) return NAME_TOO_LONG~;
	out.write_byte(AUTH_VERSION)!;
	out.write_byte((char)user.len)!;
	io::write_all(out, (char[])user)!;
	out.write_byte((char)pass.len)!;
	io::write_all(out, (char[])pass)!;
}

<*
 Decode the server's username/password reply.
 @return "true when STATUS == 0x00 (success)"
 @return? UNSUPPORTED_VERSION
*>
fn bool? decode_userpass_reply(InStream in)
{
	char ver = in.read_byte()!;
	if (ver != AUTH_VERSION) return UNSUPPORTED_VERSION~;
	char status = in.read_byte()!;
	return status == 0;
}

// --- addresses (RFC 1928 section 5, the DST.ADDR/BND.ADDR wire shape) ---

<*
 @return? UNSUPPORTED_ADDRESS_TYPE
 @return? NAME_TOO_LONG
*>
fn Address? decode_address(InStream in, Allocator allocator)
{
	Address addr;
	char raw_atype = in.read_byte()!;
	addr.atype = address_type_from_wire(raw_atype)!;
	switch (addr.atype)
	{
		case IPV4:
			io::read_all(in, &addr.ipv4)!;
		case IPV6:
			io::read_all(in, &addr.ipv6)!;
		case DOMAIN:
			char len = in.read_byte()!;
			if (len == 0) return NAME_TOO_LONG~;
			char[] name = alloc::alloc_array(allocator, char, len)[:len];
			io::read_all(in, name)!;
			addr.domain = (String)name;
	}
	char[2] port_be;
	io::read_all(in, &port_be)!;
	addr.port = (ushort)(((ushort)port_be[0] << 8) | (ushort)port_be[1]);
	return addr;
}

fn void? encode_address(OutStream out, Address addr)
{
	out.write_byte(addr.atype.wire)!;
	switch (addr.atype)
	{
		case IPV4:
			io::write_all(out, &addr.ipv4)!;
		case IPV6:
			io::write_all(out, &addr.ipv6)!;
		case DOMAIN:
			if (addr.domain.len == 0 || addr.domain.len > MAX_NAME_LEN) return NAME_TOO_LONG~;
			out.write_byte((char)addr.domain.len)!;
			io::write_all(out, (char[])addr.domain)!;
	}
	char[2] port_be = { (char)(addr.port >> 8), (char)(addr.port & 0xff) };
	io::write_all(out, &port_be)!;
}

// --- requests / replies (RFC 1928 section 4 and 6) ---

<*
 @return? UNSUPPORTED_VERSION
 @return? UNSUPPORTED_COMMAND
 @return? MALFORMED_MESSAGE : "RSV byte was not 0x00"
*>
fn Request? decode_request(InStream in, Allocator allocator)
{
	char ver = in.read_byte()!;
	if (ver != VERSION) return UNSUPPORTED_VERSION~;
	char raw_cmd = in.read_byte()!;
	Command cmd = command_from_wire(raw_cmd)!;
	char rsv = in.read_byte()!;
	if (rsv != 0) return MALFORMED_MESSAGE~;
	Address dst = decode_address(in, allocator)!;
	return { .cmd = cmd, .dst = dst };
}

fn void? encode_reply(OutStream out, ReplyCode code, Address bnd)
{
	char[3] head = { VERSION, code.wire, 0 };
	io::write_all(out, &head)!;
	encode_address(out, bnd)!;
}

fn void? encode_request(OutStream out, Command cmd, Address dst)
{
	char[3] head = { VERSION, cmd.wire, 0 };
	io::write_all(out, &head)!;
	encode_address(out, dst)!;
}

<*
 Decode the server's reply to a request.
 @return? UNSUPPORTED_VERSION
 @return? MALFORMED_MESSAGE : "RSV byte was not 0x00, or REP is not a known reply code"
 @return? UNSUPPORTED_ADDRESS_TYPE
 @return? NAME_TOO_LONG
*>
fn Reply? decode_reply(InStream in, Allocator allocator)
{
	char ver = in.read_byte()!;
	if (ver != VERSION) return UNSUPPORTED_VERSION~;
	char raw_code = in.read_byte()!;
	ReplyCode code = reply_code_from_wire(raw_code)!;
	char rsv = in.read_byte()!;
	if (rsv != 0) return MALFORMED_MESSAGE~;
	Address bnd = decode_address(in, allocator)!;
	return { .code = code, .bnd = bnd };
}

// --- UDP relay header (RFC 1928 section 7) ---

<*
 @return? MALFORMED_MESSAGE : "RSV bytes were not 0x0000"
 @return? UNSUPPORTED_FRAGMENTATION
*>
fn UdpDatagram? decode_udp_header(char[] packet, Allocator allocator)
{
	ByteReader reader;
	reader.init(packet);
	char[2] rsv;
	io::read_all(&reader, &rsv)!;
	if (rsv[0] != 0 || rsv[1] != 0) return MALFORMED_MESSAGE~;
	char frag = reader.read_byte()!;
	if (frag != 0) return UNSUPPORTED_FRAGMENTATION~;
	Address dst = decode_address(&reader, allocator)!;
	return { .dst = dst, .payload = packet[reader.index..] };
}

fn char[]? encode_udp_header(Allocator allocator, Address dst, char[] payload)
{
	ByteWriter writer;
	writer.init(allocator);
	char[3] head = { 0, 0, 0 };
	io::write_all(&writer, &head)!;
	encode_address(&writer, dst)!;
	io::write_all(&writer, payload)!;
	return writer.array_view();
}
