// socks5-server: CLI wrapper around socks5::server::Server.
module main;

import std::io;
import socks5::server;

struct Credential
{
	String username;
	String password;
}

Credential[32] g_credentials;
usz g_credential_count;

fn bool check_credentials(String username, String password)
{
	for (usz i = 0; i < g_credential_count; i++)
	{
		if (g_credentials[i].username == username && g_credentials[i].password == password) return true;
	}
	return false;
}

fn void usage()
{
	io::printn("usage: socks5-server <listen-host> <listen-port> [--allow-no-auth] [--user NAME:PASS ...]");
	io::printn("  at least one of --allow-no-auth or --user is required");
}

fn void main(String[] args)
{
	if (args.len < 3)
	{
		usage();
		return;
	}
	String host = args[1];
	int? port = args[2].to_int();
	if (catch port)
	{
		io::printfn("bad port: %s", args[2]);
		return;
	}

	bool allow_no_auth = false;
	usz i = 3;
	while (i < args.len)
	{
		if (args[i] == "--allow-no-auth")
		{
			allow_no_auth = true;
			i++;
			continue;
		}
		if (args[i] == "--user" && i + 1 < args.len)
		{
			String spec = args[i + 1];
			sz? colon = spec.index_of_char(':');
			if (catch colon)
			{
				io::printfn("bad --user spec (want NAME:PASS): %s", spec);
				return;
			}
			if (g_credential_count >= g_credentials.len)
			{
				io::printn("too many --user entries");
				return;
			}
			g_credentials[g_credential_count] = { .username = spec[:colon], .password = spec[colon + 1..] };
			g_credential_count++;
			i += 2;
			continue;
		}
		io::printfn("unknown argument: %s", args[i]);
		usage();
		return;
	}

	if (!allow_no_auth && g_credential_count == 0)
	{
		usage();
		return;
	}

	Server srv;
	if (catch err = srv.listen(host, port))
	{
		io::printfn("listen on %s:%d failed: %s", host, port, err);
		return;
	}
	io::printfn("socks5-server listening on %s:%d (no-auth=%s, accounts=%d)",
		host, port, allow_no_auth, g_credential_count);

	AuthCheckFn auth_fn = g_credential_count > 0 ? &check_credentials : null;
	if (catch err = srv.serve_forever(allow_no_auth, auth_fn))
	{
		io::printfn("server stopped: %s", err);
	}
}
