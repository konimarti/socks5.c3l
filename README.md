# socks5.c3l

A SOCKS5 proxy library for [C3](https://c3-lang.org), implementing the server
and client sides of RFC 1928 (SOCKS Protocol Version 5) and RFC 1929
(Username/Password Authentication).

## Features

- Full command set: CONNECT, BIND, UDP ASSOCIATE.
- All address types: IPv4, IPv6, domain name.
- NO AUTH and username/password authentication.
- Pure wire-format codec (`socks5::proto`), independent of sockets — fast to
  test, easy to reuse.
- Two CLI binaries: `socks5-server` and `socks5-client`, for running or
  testing a proxy from the command line.
- 63 unit tests; interop-verified against real `curl` and real HTTP/HTTPS
  traffic, not just self-pairing.

## Why

Most SOCKS5 implementations are either client-only or bolted onto something
larger. This is a standalone library: server and client, nothing else, built
to be embedded in another C3 project or run as-is.

## Install

```sh
git clone https://github.com/<you>/socks5.c3l
cd socks5.c3l
c3c build socks5-server
c3c build socks5-client
```

## Use as a library

```c3
import socks5::server;

Server srv;
srv.listen("0.0.0.0", 1080)!;
srv.serve_forever(/* allow_no_auth */ true, /* auth_check */ null)!;
```

```c3
import std::net::tcp;
import socks5::client;

TcpSocket sock = client::connect("127.0.0.1", 1080, "example.com", 443)!;
```

## Use the binaries

```sh
# Server: listen on 1080, no authentication.
./build/socks5-server 0.0.0.0 1080 --allow-no-auth

# Server: require a username/password account instead.
./build/socks5-server 0.0.0.0 1080 --user alice:secret

# Client: tunnel stdin/stdout through the proxy to a target.
./build/socks5-client 127.0.0.1:1080 example.com:80
```

## Tests

```sh
c3c test test
```

## Scope

GSSAPI authentication and UDP datagram fragmentation are not implemented —
both are rare in practice and out of scope for v1. See the commit history
for other narrowly-scoped v1 limitations.

## License

MIT — see [LICENSE](LICENSE).
