// socks5-client: a small CLI test client. Connects through a SOCKS5 proxy
// (CONNECT command) to a target, then relays stdin<->socket until EOF on
// either side. Meant for manually exercising a SOCKS5 server (ours,
// curl's, or ssh -D's) from the command line.
module main;

import std::io, std::net, std::net::tcp, std::thread, libc;
import socks5::client;

excuse { BAD_HOST_PORT }

struct HostPort
{
	String host;
	int port;
}

fn HostPort? parse_host_port(String spec)
{
	sz? colon = spec.index_of_char(':');
	if (catch colon) return BAD_HOST_PORT~;
	int? port = spec[colon + 1..].to_int();
	if (catch port) return BAD_HOST_PORT~;
	return { .host = spec[:colon], .port = port };
}

fn void usage()
{
	io::printn("usage: socks5-client <proxy-host:port> <target-host:port> [--user NAME --pass PASS]");
}

// Raw fd read/write instead of io::stdin()/io::stdout(): those go through
// libc's buffered fread/fwrite, which (for a non-tty fd) blocks trying to
// fill the entire request before returning, instead of handing back
// whatever is already available. That stalls interactive relaying — a
// typed line just sits until enough bytes accumulate to fill the buffer.
fn sz? read_raw(libc::Fd fd, char[] buf)
{
	sz n = libc::read(fd, buf.ptr, buf.len);
	if (n < 0) return io::GENERAL_ERROR~;
	return n;
}

fn void? write_all_raw(libc::Fd fd, char[] buf)
{
	usz written;
	while (written < buf.len)
	{
		sz n = libc::write(fd, &buf[written], buf.len - written);
		if (n <= 0) return io::GENERAL_ERROR~;
		written += (usz)n;
	}
}

fn int pump_socket_to_stdout(void* arg)
{
	TcpSocket* sock = (TcpSocket*)arg;
	char[4096] buf;
	while (true)
	{
		sz? n = sock.read(&buf);
		if (catch n) break;
		if (n == 0) break;
		if (catch write_all_raw(libc::STDOUT_FD, buf[:n])) break;
	}
	return 0;
}

fn void main(String[] args)
{
	if (args.len < 3)
	{
		usage();
		return;
	}
	HostPort? proxy = parse_host_port(args[1]);
	if (catch proxy)
	{
		io::printfn("bad proxy address (want host:port): %s", args[1]);
		return;
	}
	HostPort? target = parse_host_port(args[2]);
	if (catch target)
	{
		io::printfn("bad target address (want host:port): %s", args[2]);
		return;
	}

	String username = "";
	String password = "";
	usz i = 3;
	while (i + 1 < args.len)
	{
		if (args[i] == "--user") { username = args[i + 1]; i += 2; continue; }
		if (args[i] == "--pass") { password = args[i + 1]; i += 2; continue; }
		io::printfn("unknown argument: %s", args[i]);
		usage();
		return;
	}

	TcpSocket? sock = client::connect(proxy.host, proxy.port, target.host, (ushort)target.port, username, password);
	if (catch err = sock)
	{
		io::printfn("connect through proxy failed: %s", err);
		return;
	}

	Thread t;
	if (catch t.create(&pump_socket_to_stdout, &sock))
	{
		io::printn("failed to start relay thread");
		(void)sock.close();
		return;
	}

	char[4096] buf;
	while (true)
	{
		sz? n = read_raw(libc::STDIN_FD, &buf);
		if (catch n) break;
		if (n == 0) break;
		if (catch io::write_all(&sock, buf[:n])) break;
	}
	(void)sock.close(); // unblocks pump_socket_to_stdout's read with EOF
	(void)t.join();
}
