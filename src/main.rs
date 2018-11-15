extern crate chrono;
extern crate futures;
extern crate tokio;
extern crate trust_dns;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use futures::future::{lazy, ok};
use futures::{try_ready, Async, Future, Poll};
use tokio::runtime::current_thread::Runtime;
use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns::udp::UdpClientStream;

struct Timed<Fut, F>
where
    Fut: Future,
    F: FnMut(&Fut::Item, Duration),
{
    inner: Fut,
    f: F,
    start: Option<Instant>,
}

impl<Fut, F> Future for Timed<Fut, F>
where
    Fut: Future,
    F: FnMut(&Fut::Item, Duration),
{
    type Item = Fut::Item;
    type Error = Fut::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let start = self.start.get_or_insert_with(Instant::now);

        let v = try_ready!(self.inner.poll());

        let elapsed = start.elapsed();
        (self.f)(&v, elapsed);

        Ok(Async::Ready(v))
    }
}

trait TimedExt: Sized + Future {
    fn timed<F>(self, f: F) -> Timed<Self, F>
    where
        F: FnMut(&Self::Item, Duration),
    {
        Timed {
            inner: self,
            f,
            start: None,
        }
    }
}

impl<F: Future> TimedExt for F {}

fn lookup_a(
    ns: SocketAddr,
    qname: Name,
) -> impl Future<Item = Ipv4Addr, Error = trust_dns::error::ClientError> {
    lazy(move || {
        let (stream, handle) = UdpClientStream::new(ns);
        let (bg, mut client) = ClientFuture::new(stream, handle, None);

        tokio::spawn(bg);

        client
            .query(qname, DNSClass::IN, RecordType::A)
            .and_then(|response| {
                let answers = response.answers();

                if answers.len() == 0 {
                    return futures::future::err(
                        trust_dns::error::ClientErrorKind::Msg("No answers".to_string()).into(),
                    );
                }

                return match answers[0].rdata() {
                    &RData::A(ref ip) => futures::future::ok(*ip),
                    record => futures::future::err(
                        trust_dns::error::ClientErrorKind::Msg(
                            format!("Unexpected answer type; {}", record.to_record_type())
                                .to_string(),
                        )
                        .into(),
                    ),
                };
            })
    })
}

#[derive(Debug, Clone)]
struct Authority {
    name: Name,
    addr: Option<SocketAddr>,
}

fn find_socketaddr_for_name(query: &Name, recs: &[Record]) -> Option<SocketAddr> {
    recs.iter().find_map(|ref rec| {
        if rec.name() != query {
            return None;
        }
        match rec.rdata() {
            &RData::A(ip) => return Some(SocketAddr::new(IpAddr::V4(ip), 53)),
            &RData::AAAA(ip) => return Some(SocketAddr::new(IpAddr::V6(ip), 53)),
            _ => None,
        }
    })
}

fn lookup_authority(
    ns: SocketAddr,
    qname: Name,
) -> impl Future<Item = Vec<Authority>, Error = trust_dns::error::ClientError> {
    lazy(move || {
        let (stream, handle) = UdpClientStream::new(ns);
        let (bg, mut client) = ClientFuture::new(stream, handle, None);

        tokio::spawn(bg);

        client
            .query(qname, DNSClass::IN, RecordType::A)
            .and_then(|response| {
                let authority = response.name_servers();
                let additional = response.additionals();

                ok(authority
                    .iter()
                    .filter_map(|ref record| match record.rdata() {
                        &RData::NS(ref name) => Some(Authority {
                            name: name.clone(),
                            addr: find_socketaddr_for_name(name, additional),
                        }),
                        _ => None,
                    })
                    .collect())
            })
    })
}

fn main() {
    let mut runtime = Runtime::new().unwrap();

    let nsaddr = ([8, 8, 8, 8], 53).into();
    let root = ([192, 48, 79, 30], 53).into(); // j.gtld-servers.net.
    let qname = Name::from_str("noip.com").unwrap();

    let ip = runtime
        .block_on(lookup_a(nsaddr, qname.clone()).timed(|_, dur| println!("resolved in {:?}", dur)))
        .unwrap();
    println!("IP: {}", ip);
    let auth = runtime
        .block_on(lookup_authority(root, qname).timed(|_, dur| println!("resolved in {:?}", dur)))
        .unwrap();
    println!("Auth: {:?}", auth);
}
