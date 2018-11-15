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
    let (stream, handle) = UdpClientStream::new(ns);
    let (bg, mut client) = ClientFuture::new(stream, handle, None);

    tokio::spawn(bg);

    let res = client.query(qname, DNSClass::IN, RecordType::A);

    res.and_then(|response| {
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
                    format!("Unexpected answer type; {}", record.to_record_type()).to_string(),
                )
                .into(),
            ),
        };
    })
}

fn main() {
    let mut runtime = Runtime::new().unwrap();
    let nsaddr = ([8, 8, 8, 8], 53).into();
    let qname = Name::from_str("noip.com").unwrap();

    /*
    let f = time_future(lookup_a(nsaddr, qname)).then(|r| match r {
        Ok(r) => {
            println!("resolved in {}ms", r.elapsed_ms());
            r.result
        }
        _ => unreachable!(),
    });
    */

    let ip = runtime.block_on(lazy(|| lookup_a(nsaddr, qname))).unwrap();
    //let ip = runtime.block_on(f).unwrap();
    println!("IP: {}", ip);
}
