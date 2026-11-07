// Shared bidirectional TCP relay, used once a CONNECT or BIND target
// connection is established. One cooperative poll loop instead of a
// thread per direction: avoids the shutdown-race shape a two-thread relay
// would need to get right twice (once per command).
//
// Readability via poll's ANY_READ bit was empirically verified against
// real loopback sockets, including the peer-close case: a closed peer
// shows up as ANY_READ-readable with a 0-byte read (EOF), not as a
// separate DISCONNECT/HUP bit, so EOF is detected via `read() == 0`, not
// by checking PollEvent.DISCONNECT.
module socks5::relay;

import std::net, std::io, std::time;

// No data in either direction for this long: close the relay. Prevents a
// dead-but-not-closed peer (either the client or the dialed target) from
// pinning the relay thread and its sockets open forever.
const Duration IDLE_TIMEOUT = (Duration)(300L * time::SEC);
const usz BUFFER_SIZE = 16384;

fn bool readable(Poll p) => ((ushort)p.revents & (ushort)PollSubscribe.ANY_READ) != 0;

<*
 Relay bytes bidirectionally between two already-connected sockets until
 either side reaches EOF, either side errors, or IDLE_TIMEOUT passes with
 no activity on either side. Closing both sockets is the caller's
 responsibility.
*>
fn void relay_bidirectional(Socket* a, Socket* b)
{
	char[BUFFER_SIZE] buf_a;
	char[BUFFER_SIZE] buf_b;
	Poll[2] polls = {
		{ .socket = a.sock, .events = ANY_READ },
		{ .socket = b.sock, .events = ANY_READ },
	};
	while (true)
	{
		ulong? n = net::poll(polls[0..], IDLE_TIMEOUT);
		if (catch n) return;
		if (!n) return; // idle timeout
		if (readable(polls[0]) && !pump(a, b, &buf_a)) return;
		if (readable(polls[1]) && !pump(b, a, &buf_b)) return;
	}
}

fn bool pump(Socket* src, Socket* dst, char[] buf)
{
	sz? got = src.read(buf);
	if (catch got) return false;
	if (got == 0) return false; // EOF
	if (catch io::write_all(dst, buf[:got])) return false;
	return true;
}
