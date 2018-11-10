extern crate chrono;
extern crate futures;
extern crate tokio;
extern crate trust_dns;

use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

//use futures::future::lazy;
use futures::Future;
use tokio::prelude::future::lazy;
use tokio::runtime::current_thread::Runtime;
use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use trust_dns::udp::UdpClientStream;

struct TimedFutureResult<T, E> {
    elapsed: Duration,
    result: Result<T, E>,
}

impl<T, E> TimedFutureResult<T, E> {
    pub fn elapsed_ms(&self) -> i64 {
        return (self.elapsed.as_secs() * 1000 + (self.elapsed.subsec_nanos() / 1000000) as u64)
            as i64;
    }
}

fn time_future<F: Future>(f: F) -> impl Future<Item = TimedFutureResult<F::Item, F::Error>> {
    lazy(|| {
        let start = Instant::now();

        f.then(move |result| {
            futures::future::ok::<TimedFutureResult<F::Item, F::Error>, ()>(TimedFutureResult {
                elapsed: start.elapsed(),
                result: result,
            })
        })
    })
}

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
