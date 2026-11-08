# socks5.c3l

A SOCKS5 proxy library for [C3](https://c3-lang.org), implementing the server
and client sides of RFC 1928 (SOCKS Protocol Version 5) and RFC 1929
(Username/Password Authentication).

## Features

- Full command set: CONNECT, BIND, UDP ASSOCIATE.
- All address types: IPv4, IPv6, domain name.
- NO AUTH and username/password authentication.
- Pure wire format codec (`socks5::proto`), independent of sockets, so it is
  fast to test and easy to reuse.
- Two CLI binaries: `socks5-server` and `socks5-client`, for running or
  testing a proxy from the command line.
- 88 unit tests; interop verified against real `curl` and real HTTP/HTTPS
  traffic, not just self pairing.

## Why

Most SOCKS5 implementations only cover the client, or are bolted onto
something larger. This is a standalone library: server and client, nothing
else, built to be embedded in another C3 project or run as is.

## Install

With [c3l](https://github.com/konimarti/c3l), the C3 package manager:

```sh
c3l add github.com/konimarti/socks5.c3l
```

Or clone it directly and build with `c3c`:

```sh
git clone https://github.com/konimarti/socks5.c3l
cd socks5.c3l
c3c build socks5-server
c3c build socks5-client
```

## Use as a library

```c3
import socks5::server;

Socks5Server srv;
srv.listen("0.0.0.0", 1080)!;
srv.serve_forever(/* allow_no_auth */ true, /* auth_check */ null)!;
```

```c3
import std::net::tcp;
import socks5::client;

TcpSocket sock = client::connect("127.0.0.1", 1080, "example.com", 443)!;
```

`client` and `server` are plain module names, not aliases, so if a project
also imports another protocol's `client` or `server` module, C3 will reject
any bare call as ambiguous. Qualify the call with the full path in that
case, which always resolves regardless of what else is imported:

```c3
socks5::client::connect("127.0.0.1", 1080, "example.com", 443)!;
```

Types are named more specifically (`Socks5Server`, `Socks5Address`, ...)
rather than, say, a bare `Server`/`Address`: a type is referenced in every
variable declaration and function signature that touches it, not just
once per call, so qualifying away a collision each time would be far more
intrusive than for an occasional function call.

## Use the binaries

```sh
# Server: listen on 1080, no authentication.
./build/socks5-server 0.0.0.0 1080 --allow-no-auth

# Server: require a username/password account instead.
./build/socks5-server 0.0.0.0 1080 --user alice:secret

# Client: tunnel stdin/stdout through the proxy to a target.
./build/socks5-client 127.0.0.1:1080 example.com:80
```

### Manual testing with `nc`

`socks5-client` relays stdin/stdout through the proxy, so it can stand in
for one end of a plain `nc` session. With three terminals:

```sh
# Terminal 1: the target `nc` connects out to.
nc -l 127.0.0.1 9000

# Terminal 2: the proxy. 127.0.0.1 is a loopback address, so it needs
# --allow-private; drop that flag when the target is a real host.
./build/socks5-server 127.0.0.1 1080 --allow-no-auth --allow-private

# Terminal 3: the client, tunnelling through the proxy to the target.
./build/socks5-client 127.0.0.1:1080 127.0.0.1:9000
```

Typing in terminal 1 or terminal 3 now relays to the other, through the
proxy, both ways. Terminal input is line buffered, so press Enter to send.

With a username/password account instead of `--allow-no-auth`:

```sh
./build/socks5-server 127.0.0.1 1080 --user alice:secret
./build/socks5-client 127.0.0.1:1080 127.0.0.1:9000 --user alice --pass secret
```

## Tests

```sh
c3c test test
```

## Scope

GSSAPI authentication and UDP datagram fragmentation are not implemented;
both are rare in practice and out of scope for v1. See the commit history
for other narrowly scoped v1 limitations.

## License

MIT, see [LICENSE](LICENSE).
