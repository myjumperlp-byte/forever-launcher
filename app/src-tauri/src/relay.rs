//! Loopback relay.
//!
//! macOS refuses a game's connections to private addresses (Local Network privacy) unless the player grants it,
//! and it does so silently: the client reports "you have been disconnected" without a packet leaving the machine.
//! Loopback is always allowed, so the client is pointed at 127.0.0.1 and this relay forwards those connections to
//! the real server. TLS stays end to end (certificate and session key never leave client and server), which is why
//! the portal name in the client's configuration does not have to change.
//!
//! The server has to hand out 127.0.0.1 for the world port (realmlist address/localAddress) as well, because the
//! client takes that address from the login answer and would otherwise head for the blocked private address again.

use crate::i18n::tf;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Runs until it is dropped: dropping it stops every listener of this relay.
pub struct Relay {
    stop: Arc<AtomicBool>,
    ports: Vec<u16>,
}

impl Relay {
    /// Listens on 127.0.0.1:<port> for every port and forwards each connection to the same port on `target`.
    /// A port that is already taken is an error for the player, never a start that silently does nothing.
    pub fn start(target: &str, ports: &[u16]) -> Result<Self, String> {
        let pairs: Vec<(u16, u16)> = ports.iter().map(|p| (*p, *p)).collect();
        Self::start_with(target, &pairs)
    }

    /// Same, with an explicit (listen port, target port) pair; a listen port of 0 lets the system pick a free one.
    pub fn start_with(target: &str, pairs: &[(u16, u16)]) -> Result<Self, String> {
        let mut listeners = Vec::new();
        for (listen, remote) in pairs {
            let address = SocketAddr::from(([127, 0, 0, 1], *listen));
            // Rust's bind sets SO_REUSEADDR, and BSD lets that share a port with another listener: binding alone
            // would succeed while the game talks to the other process. Asking first is what makes it an error.
            if *listen != 0
                && TcpStream::connect_timeout(&address, Duration::from_millis(400)).is_ok()
            {
                return Err(tf("relay_busy", &[&address]));
            }
            let listener =
                TcpListener::bind(address).map_err(|e| tf("relay_bind", &[&address, &e]))?;
            listener
                .set_nonblocking(true)
                .map_err(|e| tf("relay_bind", &[&address, &e]))?;
            let bound = listener
                .local_addr()
                .map_err(|e| tf("relay_bind", &[&address, &e]))?
                .port();
            listeners.push((bound, *remote, listener));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut ports = Vec::with_capacity(listeners.len());
        for (listen, remote, listener) in listeners {
            ports.push(listen);
            let stop = stop.clone();
            let target = target.to_string();
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((client, peer)) => {
                            // BSD (macOS) lets an accepted socket inherit the listener's non-blocking mode: without
                            // this the copy below fails with WouldBlock at once and the game sees its socket closed
                            if let Err(e) = client.set_nonblocking(false) {
                                crate::log_line(format!(
                                    "relay: {listen} {peer} blieb nicht blockierend: {e}"
                                ));
                            }
                            crate::log_line(format!("relay: {listen} verbunden von {peer}"));
                            let target = target.clone();
                            thread::spawn(move || forward(client, &target, remote, listen));
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(40))
                        }
                        Err(e) => {
                            // without a line here the relay would look alive while it accepts nothing any more
                            crate::log_line(format!(
                                "relay: {listen} nimmt keine Verbindungen mehr an: {e}"
                            ));
                            break;
                        }
                    }
                }
            });
        }
        Ok(Self { stop, ports })
    }

    /// The ports this relay actually listens on (for the log).
    pub fn ports(&self) -> &[u16] {
        &self.ports
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Copies both directions until the game or the server closes; one direction ending closes both.
fn forward(client: TcpStream, target: &str, port: u16, listen: u16) {
    let upstream = match TcpStream::connect((target, port)) {
        Ok(upstream) => upstream,
        Err(e) => {
            // silence here is what made a broken relay look like a broken server
            crate::log_line(format!(
                "relay: {listen} konnte {target}:{port} nicht erreichen: {e}"
            ));
            return;
        }
    };
    let (mut client_read, mut upstream_read) = match (client.try_clone(), upstream.try_clone()) {
        (Ok(client_read), Ok(upstream_read)) => (client_read, upstream_read),
        _ => {
            crate::log_line(format!("relay: {listen} konnte den Socket nicht teilen"));
            return;
        }
    };
    let mut client_write = client;
    let mut upstream_write = upstream;
    let up = thread::spawn(move || {
        // a count of 0 Bytes must not hide the reason: an error reads as one
        match io::copy(&mut client_read, &mut upstream_write) {
            Ok(sent) => crate::log_line(format!(
                "relay: {listen} client->server Ende nach {sent} Bytes"
            )),
            Err(e) => crate::log_line(format!("relay: {listen} client->server abgebrochen: {e}")),
        }
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    match io::copy(&mut upstream_read, &mut client_write) {
        Ok(back) => crate::log_line(format!(
            "relay: {listen} server->client Ende nach {back} Bytes"
        )),
        Err(e) => crate::log_line(format!("relay: {listen} server->client abgebrochen: {e}")),
    }
    let _ = client_write.shutdown(Shutdown::Write);
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// An echo server on an ephemeral port, standing in for the game server.
    fn echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("echo listener");
        let port = listener.local_addr().expect("address").port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (mut read, mut write) = (stream.try_clone().expect("clone"), stream);
                thread::spawn(move || {
                    let _ = io::copy(&mut read, &mut write);
                });
            }
        });
        port
    }

    #[test]
    fn forwards_both_directions() {
        let echo_port = echo_server();
        // the relay asks the system for a free port, so the test cannot race another process for a fixed one
        let relay = Relay::start_with("127.0.0.1", &[(0, echo_port)]).expect("relay starts");
        let relay_port = relay.ports()[0];
        assert_ne!(
            relay_port, 0,
            "relay reports the port it actually listens on"
        );
        let mut client = TcpStream::connect(("127.0.0.1", relay_port)).expect("connect");
        client.set_read_timeout(Some(Duration::from_secs(5))).ok();
        client.write_all(b"forever").expect("write");
        let mut answer = [0u8; 7];
        client.read_exact(&mut answer).expect("read");
        assert_eq!(&answer, b"forever");
    }

    #[test]
    fn reports_a_port_that_is_already_taken() {
        let held = TcpListener::bind("127.0.0.1:0").expect("held listener");
        let port = held.local_addr().expect("address").port();
        let error = Relay::start("127.0.0.1", &[port]).err().expect("must fail");
        assert!(
            error.contains(&port.to_string()),
            "message names the port: {error}"
        );
    }
}
