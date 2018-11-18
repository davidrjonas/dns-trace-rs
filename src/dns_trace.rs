use std::fmt;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use futures::future::{err, ok};
use futures::{Async, Future, Poll};
use trust_dns::error::{ClientError, ClientErrorKind};
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};
//use trust_dns_proto::op::response_code::ResponseCode;
//use trust_dns::client::client_future::ClientResponse;
use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::udp::UdpClientStream;
use trust_dns_proto::xfer::DnsResponse;

const MAX_STEPS: usize = 20;

#[derive(Debug)]
pub enum Error {
    DeadEnd(Vec<Step>),
    TooManySteps(Vec<Step>),
}

#[derive(Debug)]
pub struct Step {
    pub source: Authority,
    pub result: Result<DnsResponse, ClientError>,
    pub elapsed: Duration,
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.result {
            Ok(ref resp) => {
                let answer = if resp.answer_count() > 0 {
                    match resp.answers()[0].rdata() {
                        &RData::A(ip) => ip.to_string(),
                        _ => "Unknown".to_string(),
                    }
                } else {
                    "None".to_string()
                };

                write!(
                    f,
                    "{}: {:?}, code: {:?}, answers: {}, authority: {}, answer: {}",
                    self.source,
                    self.elapsed,
                    resp.response_code(),
                    resp.answer_count(),
                    resp.name_server_count(),
                    answer
                )
            }
            Err(ref e) => write!(f, "{}: {:?}", self.source, e),
        }
    }
}

type ProgressFn = fn(&Step) -> ();

#[derive(Debug, Clone)]
pub struct Authority {
    name: Name,
    addr: Option<SocketAddr>,
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}[{}]",
            self.name,
            self.addr
                .map(|addr| addr.to_string())
                .unwrap_or("Unknown".to_string())
        )
    }
}

impl Authority {
    fn root_hints() -> Vec<Authority> {
        vec![
            // a.root-servers.net.
            // 198.41.0.4
            Authority {
                name: Name::parse("a.root-servers.net.", None).unwrap(),
                addr: Some(([198, 41, 0, 4], 53).into()),
            },
            // b.root-servers.net.
            // 199.9.14.201
            Authority {
                name: Name::parse("b.root-servers.net.", None).unwrap(),
                addr: Some(([199, 9, 14, 201], 53).into()),
            },
            // c.root-servers.net.
            // 192.33.4.12
            Authority {
                name: Name::parse("c.root-servers.net.", None).unwrap(),
                addr: Some(([192, 33, 4, 12], 53).into()),
            },
            // d.root-servers.net.
            // 199.7.91.13
            Authority {
                name: Name::parse("d.root-servers.net.", None).unwrap(),
                addr: Some(([199, 7, 91, 13], 53).into()),
            },
            // e.root-servers.net.
            // 192.203.230.10
            Authority {
                name: Name::parse("e.root-servers.net.", None).unwrap(),
                addr: Some(([192, 203, 230, 10], 53).into()),
            },
            // f.root-servers.net.
            // 192.5.5.241
            Authority {
                name: Name::parse("f.root-servers.net.", None).unwrap(),
                addr: Some(([192, 5, 5, 241], 53).into()),
            },
            // g.root-servers.net.
            // 192.112.36.4
            Authority {
                name: Name::parse("g.root-servers.net.", None).unwrap(),
                addr: Some(([192, 112, 36, 4], 53).into()),
            },
            // h.root-servers.net.
            // 198.97.190.53
            Authority {
                name: Name::parse("h.root-servers.net.", None).unwrap(),
                addr: Some(([198, 97, 190, 53], 53).into()),
            },
            // i.root-servers.net.
            // 192.36.148.17
            Authority {
                name: Name::parse("i.root-servers.net.", None).unwrap(),
                addr: Some(([192, 36, 148, 17], 53).into()),
            },
            // j.root-servers.net.
            // 192.58.128.30
            Authority {
                name: Name::parse("j.root-servers.net.", None).unwrap(),
                addr: Some(([192, 58, 128, 30], 53).into()),
            },
        ]
    }

    fn lookup(&self, qname: &Name) -> impl Future<Item = DnsResponse, Error = ClientError> {
        let name = qname.clone();

        self.addr
            .map_or(
                err(ClientErrorKind::Msg("no addr for authority".to_string()).into()),
                |addr| {
                    let (stream, handle) = UdpClientStream::new(addr);
                    let (bg, client) = ClientFuture::new(stream, handle, None);

                    tokio::spawn(bg);

                    ok(client)
                },
            )
            .and_then(move |mut client| client.query(name, DNSClass::IN, RecordType::A))
    }
}

fn find_socketaddr_for_name(query: &Name, recs: &[Record]) -> Option<SocketAddr> {
    recs.iter().find_map(|ref rec| {
        if rec.name() != query {
            return None;
        }
        match rec.rdata() {
            &RData::A(ip) => Some(SocketAddr::new(IpAddr::V4(ip), 53)),
            &RData::AAAA(ip) => Some(SocketAddr::new(IpAddr::V6(ip), 53)),
            _ => None,
        }
    })
}

fn dns_response_to_ns(res: &DnsResponse) -> Vec<Authority> {
    let authority = res.name_servers();
    let additional = res.additionals();

    authority
        .iter()
        .filter_map(|ref record| match record.rdata() {
            &RData::NS(ref name) => Some(Authority {
                name: name.clone(),
                addr: find_socketaddr_for_name(name, additional),
            }),
            _ => None,
        })
        .collect()
}

pub struct DnsTrace {
    name: Name,
    progress_fn: Option<ProgressFn>,
    ns: Vec<Authority>,
    steps: Vec<Step>,
    current: Option<Authority>,
    pending: Option<Box<Future<Item = DnsResponse, Error = ClientError>>>,
    start: Instant,
}

impl DnsTrace {
    fn promote_lookup(&mut self) {
        self.start = Instant::now();
        self.current = self.ns.pop();
        self.pending = match self.current {
            Some(ref ns) => Some(Box::new(ns.lookup(&self.name))),
            None => None,
        };
    }
}

impl Future for DnsTrace {
    type Item = Vec<Step>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if self.pending.is_none() {
            self.promote_lookup();
        }

        let result: Result<DnsResponse, ClientError>;

        // Only need a mutable ref to `pending` for this scope
        {
            let f = match self.pending {
                Some(ref mut f) => f,
                None => unreachable!(),
            };

            // Early return if the current future is not ready
            result = match f.poll() {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(t)) => Ok(t),
                Err(e) => Err(e),
            };
        }

        let step = Step {
            source: self.current.as_ref().unwrap().clone(),
            result: result,
            elapsed: self.start.elapsed(),
        };

        let mut done = false;

        if let Ok(ref res) = step.result {
            self.pending = None;
            if res.header().response_code() == 0 {
                if res.answer_count() > 0 {
                    done = true;
                } else if res.name_server_count() > 0 {
                    self.ns = dns_response_to_ns(&res);
                }
            }
        }

        if let Some(p) = self.progress_fn {
            (p)(&step);
        }

        self.steps.push(step);

        if done {
            let steps = mem::replace(&mut self.steps, Vec::new());
            Ok(Async::Ready(steps))
        } else {
            if self.ns.is_empty() {
                let steps = mem::replace(&mut self.steps, Vec::new());
                Err(Error::DeadEnd(steps))
            } else if self.steps.len() >= MAX_STEPS {
                let steps = mem::replace(&mut self.steps, Vec::new());
                Err(Error::TooManySteps(steps))
            } else {
                Ok(Async::NotReady)
            }
        }
    }
}

pub fn trace(qname: &Name, progress: Option<ProgressFn>) -> DnsTrace {
    let ns = Authority::root_hints();

    DnsTrace {
        name: qname.clone(),
        progress_fn: progress,
        steps: vec![],
        ns: ns,
        current: None,
        pending: None,
        start: Instant::now(),
    }
}
