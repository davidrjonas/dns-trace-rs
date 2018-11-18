extern crate chrono;
extern crate futures;
extern crate tokio;
extern crate trust_dns;
extern crate trust_dns_proto;

use std::str::FromStr;
//use std::time::Duration;

use tokio::runtime::current_thread::Runtime;
use trust_dns::rr::Name;

mod dns_trace;
use dns_trace::trace;

//mod timed;
//use timed::TimedExt;

fn main() {
    let mut runtime = Runtime::new().unwrap();

    let qname = Name::from_str("noip.co.uk").unwrap();

    let _trace = runtime
        .block_on(trace(&qname, Some(|s| println!("Step: {}", s))))
        .unwrap();

    //println!("Trace: {:?}", trace);
}
