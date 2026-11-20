//! An implementation of RFC 8305. See [`connect`]

use std::net::{SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use std::{io, net::SocketAddr};

use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt as _, TryFutureExt, select_biased};
use itertools::Itertools;
use tokio::time::{Instant, sleep_until};

pub const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(200);

/// Attempt to connect to any of `addrs`. Returns the first successful connection.
///
/// This is an implementation of RFC 8305, which will walk the list of addresses, alternating
/// between IPv6 and IPv4, and attempt a connection to a new address every [`HAPPY_EYEBALLS_DELAY`].
///
/// If all connection attempts fail, the first error is returned.
///
/// # Example
/// ```no_run
/// use domain_fronting::happy_eyeballs;
/// use tokio::net::TcpStream;
/// async fn tcp_connect(addrs: &[std::net::SocketAddr]) -> Result<TcpStream, std::io::Error> {
///     happy_eyeballs::connect(addrs, async |addr| {
///         TcpStream::connect(addr).await
///     }).await
/// }
/// ```
pub async fn connect<T>(
    addrs: &[SocketAddr],
    connect: impl AsyncFn(SocketAddr) -> io::Result<T>,
) -> io::Result<T> {
    // Re-order the addresses such that we alternate between IPv6 and IPv4
    let addrs_v6 = ipv6_addrs(addrs).map(SocketAddr::from);
    let addrs_v4 = ipv4_addrs(addrs).map(SocketAddr::from);
    let addrs = addrs_v6.interleave(addrs_v4);

    let mut pending_attempts = FuturesUnordered::new();

    // Keep the first encountered error here, as it's hopefully the most relevant.
    let mut first_error = None;
    let mut keep_err = |err| {
        if first_error.is_none() {
            first_error = Some(err);
        }
    };

    for addr in addrs {
        log::trace!("Attempting connection to {addr:?}");

        let future = connect(addr)
            .inspect_ok(move |_| log::trace!("Connection to {addr:?} succeeded."))
            .inspect_err(move |e| log::trace!("Failed to connect to {addr:?}: {e:?}"));
        pending_attempts.push(future);

        let next_addr_at = Instant::now() + HAPPY_EYEBALLS_DELAY;

        loop {
            select_biased! {
                done = pending_attempts.next() => match done {
                    Some(Ok(t)) => return Ok(t),
                    Some(Err(e)) => keep_err(e),
                    None => break,
                },
                _ = sleep_until(next_addr_at).fuse() => break,
            }
        }
    }

    // No more addresses to try. Wait for pending attempts to complete.
    while let Some(result) = pending_attempts.next().await {
        match result {
            Ok(t) => return Ok(t),
            Err(e) => keep_err(e),
        }
    }

    // We failed. Return the first error.
    match first_error {
        Some(e) => Err(e),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No addresses specified",
        )),
    }
}

/// Get all IPv6 socket addrs from a list
fn ipv6_addrs(addrs: &[SocketAddr]) -> impl Iterator<Item = SocketAddrV6> {
    addrs.iter().filter_map(|&addr| match addr {
        SocketAddr::V6(v6) => Some(v6),
        SocketAddr::V4(..) => None,
    })
}

/// Get all IPv4 socket addrs from a list
fn ipv4_addrs(addrs: &[SocketAddr]) -> impl Iterator<Item = SocketAddrV4> {
    addrs.iter().filter_map(|&addr| match addr {
        SocketAddr::V4(v4) => Some(v4),
        SocketAddr::V6(..) => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;

    fn v4() -> SocketAddr {
        "192.0.2.1:443".parse().unwrap()
    }

    fn v6() -> SocketAddr {
        "[2001:db8::1]:443".parse().unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn succeeds_on_slow_last_addr() {
        let result = connect(&[v6(), v4()], async |addr| {
            if addr.is_ipv6() {
                pending::<io::Result<SocketAddr>>().await // v6 hangs forever
            } else {
                // v4 succeeds after a while
                sleep_until(Instant::now() + Duration::from_millis(300)).await;
                Ok(addr)
            }
        })
        .await;
        assert_eq!(result.unwrap(), v4(), "second attempt succeeded");
    }

    #[tokio::test(start_paused = true)]
    async fn returns_first_addr_without_starting_the_rest() {
        // if the first attempt succeeds instantly, the second must never be attempted.
        let attempted = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let seen = attempted.clone();
        let result = connect(&[v6(), v4()], async |addr| {
            seen.borrow_mut().push(addr);
            Ok(addr)
        })
        .await;
        assert_eq!(result.unwrap(), v6(), "first attempt succeeds");
        assert_eq!(attempted.borrow().len(), 1, "only one attempt was made");
    }

    #[tokio::test(start_paused = true)]
    async fn all_fail_returns_first_error() {
        let result: io::Result<SocketAddr> = connect(&[v6(), v4()], async |addr| {
            if addr.is_ipv6() {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Err(io::ErrorKind::Other.into())
            }
        })
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
