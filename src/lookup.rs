use std::net::{Ipv4Addr, SocketAddr};

use futures::future::{err, ok};
use futures::Future;
use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::error::{ClientError, ClientErrorKind};
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns::udp::UdpClientStream;

fn lookup_a(ns: SocketAddr, qname: Name) -> impl Future<Item = Ipv4Addr, Error = ClientError> {
    lazy(move || {
        let (stream, handle) = UdpClientStream::new(ns);
        let (bg, mut client) = ClientFuture::new(stream, handle, None);

        tokio::spawn(bg);

        client
            .query(qname, DNSClass::IN, RecordType::A)
            .and_then(|response| {
                let answers = response.answers();

                if answers.len() == 0 {
                    return err(ClientErrorKind::Msg("No answers".to_string()).into());
                }

                return match answers[0].rdata() {
                    &RData::A(ref ip) => ok(*ip),
                    record => err(ClientErrorKind::Msg(
                        format!("Unexpected answer type; {}", record.to_record_type()).to_string(),
                    )
                    .into()),
                };
            })
    })
}
