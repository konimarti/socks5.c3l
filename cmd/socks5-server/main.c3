// socks5-server: CLI wrapper around socks5::server::Server.
module main;

import std::io, std::crypto, std::os::env, std::io::file;
import socks5::server, socks5::acl;

struct Credential
{
	String username;
	String password;
}

Credential[64] g_credentials;
usz g_credential_count;

fn bool equal_constant_time(String a, String b)
{
	if (a.len != b.len) return false;
	return crypto::safe_compare(a.ptr, b.ptr, a.len);
}

<*
 Checks every account rather than returning on the first match. Both
 comparisons for a given account are always made (not short-circuited
 by `&&` on the first), and both use safe_compare rather than `==`, so
 response latency doesn't leak which account — or even whether the
 username alone matched — any faster than a full miss.
*>
fn bool check_credentials(String username, String password)
{
	bool found = false;
	for (usz i = 0; i < g_credential_count; i++)
	{
		bool user_ok = equal_constant_time(g_credentials[i].username, username);
		bool pass_ok = equal_constant_time(g_credentials[i].password, password);
		if (user_ok && pass_ok) found = true;
	}
	return found;
}

<*
 Adds one "NAME:PASS" account. Returns false on a malformed spec, an
 out-of-range length, or a full table — logging is the caller's job,
 since only the caller knows which source (CLI flag, file, env var)
 a given spec came from.
 @param spec : "NAME:PASS; both parts must be 1..255 bytes, the RFC 1929 ULEN/PLEN range"
*>
fn bool add_credential(String spec)
{
	sz? colon = spec.index_of_char(':');
	if (catch colon) return false;
	String username = spec[:colon];
	String password = spec[colon + 1..];
	if (username.len == 0 || username.len > 255) return false;
	if (password.len == 0 || password.len > 255) return false;
	if (g_credential_count >= g_credentials.len) return false;
	g_credentials[g_credential_count] = { .username = username, .password = password };
	g_credential_count++;
	return true;
}

<*
 Parses accounts out of a blob of text, one "NAME:PASS" per line.
 Blank lines and lines starting with '#' are skipped. Used for
 --users-file: no comma-splitting here, unlike load_users_list below —
 a file is the one source where a password containing a literal comma
 is plausible, and silently truncating it at the comma would be a
 real (not just theoretical) way to lock an account out.
*>
fn usz load_users_lines(String text)
{
	usz added = 0;
	foreach (String line : text.tsplit("\n"))
	{
		String trimmed = line.trim();
		if (trimmed.len == 0 || trimmed[0] == '#') continue;
		if (g_credential_count >= g_credentials.len)
		{
			io::printn("warning: too many accounts, ignoring the rest of the users file");
			break;
		}
		if (add_credential(trimmed)) { added++; }
		else { io::printfn("warning: skipping malformed account spec: %s", trimmed); }
	}
	return added;
}

<*
 Parses accounts out of a comma- or newline-separated list: used for
 the SOCKS5_USERS environment variable and a .env file's SOCKS5_USERS=
 line, where the whole list is conventionally one shell-friendly value
 rather than a file with one account per line.
*>
fn usz load_users_list(String text)
{
	usz added = 0;
	foreach (String line : text.tsplit("\n"))
	{
		String trimmed_line = line.trim();
		if (trimmed_line.len == 0 || trimmed_line[0] == '#') continue;
		foreach (String entry : trimmed_line.tsplit(","))
		{
			String trimmed = entry.trim();
			if (trimmed.len == 0) continue;
			if (g_credential_count >= g_credentials.len)
			{
				io::printn("warning: too many accounts, ignoring the rest of SOCKS5_USERS");
				return added;
			}
			if (add_credential(trimmed)) { added++; }
			else { io::printfn("warning: skipping malformed account spec: %s", trimmed); }
		}
	}
	return added;
}

<*
 Strips one matching pair of leading/trailing quotes (' or "), the way
 a shell would when sourcing a .env file — we don't source it, so we
 have to do this ourselves or a quoted SOCKS5_USERS="..." value ends
 up with the quote characters baked into the first and last account.
*>
fn String strip_quotes(String s)
{
	if (s.len < 2) return s;
	char first = s[0];
	char last = s[s.len - 1];
	if ((first == '"' || first == '\'') && first == last) return s[1:s.len - 2];
	return s;
}

<*
 Loads a dotenv-style file (KEY=VALUE per line) and, if it defines
 SOCKS5_USERS, parses that value the same way the environment variable
 is parsed. Other keys are ignored — this isn't a general dotenv
 loader, just enough to pull credentials from a .env file without a
 shell sourcing it into the real environment first.
*>
fn usz load_env_file(String path)
{
	char[]? data = file::load(mem, path);
	if (catch data)
	{
		io::printfn("could not read env file %s", path);
		return 0;
	}
	usz added = 0;
	foreach (String line : ((String)data).tsplit("\n"))
	{
		String trimmed = line.trim();
		if (trimmed.len == 0 || trimmed[0] == '#') continue;
		sz? eq = trimmed.index_of_char('=');
		if (catch eq) continue;
		if (trimmed[:eq] == "SOCKS5_USERS")
		{
			added += load_users_list(strip_quotes(trimmed[eq + 1..]));
		}
	}
	return added;
}

fn void usage()
{
	io::printn("usage: socks5-server <listen-host> <listen-port> [options]");
	io::printn("  --allow-no-auth           allow clients with no credentials");
	io::printn("  --user NAME:PASS          add one account (repeatable; visible in ps/history)");
	io::printn("  --users-file PATH         add accounts from a file, one NAME:PASS per line");
	io::printn("  --env-file PATH           add accounts from a .env file's SOCKS5_USERS=... line");
	io::printn("  --max-connections N       cap concurrent connections (default 1024)");
	io::printn("  --allow-private           allow CONNECT/UDP targets in loopback/private/link-local ranges");
	io::printn("  (the SOCKS5_USERS environment variable is always checked, comma- or newline-separated)");
	io::printn("  at least one of --allow-no-auth or an account source is required");
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
		io::printfn("bad port (want 1..65535): %s", args[2]);
		return;
	}
	if (port < 1 || port > 0xffff)
	{
		io::printfn("bad port (want 1..65535): %s", args[2]);
		return;
	}

	// Loaded with the persistent allocator (`mem`), not `tmem`: these
	// slices are kept in g_credentials for the life of the process,
	// and a temp allocator's contents aren't guaranteed to survive
	// past the scope that created them.
	if (try env_users = env::get_var(mem, "SOCKS5_USERS")) load_users_list(env_users);

	bool allow_no_auth = false;
	bool allow_private = false;
	usz max_connections = server::DEFAULT_MAX_CONNECTIONS;
	usz i = 3;
	while (i < args.len)
	{
		if (args[i] == "--allow-no-auth")
		{
			allow_no_auth = true;
			i++;
			continue;
		}
		if (args[i] == "--allow-private")
		{
			allow_private = true;
			i++;
			continue;
		}
		if (args[i] == "--user" && i + 1 < args.len)
		{
			if (!add_credential(args[i + 1]))
			{
				io::printfn("bad --user spec (want NAME:PASS) or too many accounts: %s", args[i + 1]);
				return;
			}
			i += 2;
			continue;
		}
		if (args[i] == "--users-file" && i + 1 < args.len)
		{
			char[]? data = file::load(mem, args[i + 1]);
			if (catch data)
			{
				io::printfn("could not read users file: %s", args[i + 1]);
				return;
			}
			load_users_lines((String)data);
			i += 2;
			continue;
		}
		if (args[i] == "--env-file" && i + 1 < args.len)
		{
			load_env_file(args[i + 1]);
			i += 2;
			continue;
		}
		if (args[i] == "--max-connections" && i + 1 < args.len)
		{
			int? n = args[i + 1].to_int();
			if (catch n)
			{
				io::printfn("bad --max-connections (want a positive integer): %s", args[i + 1]);
				return;
			}
			if (n < 1)
			{
				io::printfn("bad --max-connections (want a positive integer): %s", args[i + 1]);
				return;
			}
			max_connections = (usz)n;
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

	acl::configure(allow_private);

	Server srv;
	if (catch err = srv.listen(host, port))
	{
		io::printfn("listen on %s:%d failed: %s", host, port, err);
		return;
	}
	io::printfn("socks5-server listening on %s:%d (no-auth=%s, accounts=%d, max-connections=%d, allow-private=%s)",
		host, port, allow_no_auth, g_credential_count, max_connections, allow_private);

	AuthCheckFn auth_fn = g_credential_count > 0 ? &check_credentials : null;
	if (catch err = srv.serve_forever(allow_no_auth, auth_fn, max_connections))
	{
		io::printfn("server stopped: %s", err);
	}
}
