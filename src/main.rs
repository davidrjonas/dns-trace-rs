#[macro_use]
extern crate clap;
extern crate futures;
extern crate rand;
extern crate tokio;
extern crate trust_dns;
extern crate trust_dns_proto;

use std::str::FromStr;

use clap::{App, Arg};
use tokio::runtime::current_thread::Runtime;
use trust_dns::rr::Name;

mod dns_trace;
use dns_trace::trace;

fn main() {
    let matches = App::new("dns-trace")
        .about("Performs DNS queries starting at the root Internet name servers following the specified authorities until it finds an answer.")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::with_name("HOST")
             .help("The hostname to query")
             .required(true)
             .index(1))
        .get_matches();

    let qname = Name::from_str(matches.value_of("HOST").unwrap()).unwrap();

    let mut runtime = Runtime::new().unwrap();

    let _trace = runtime
        .block_on(trace(&qname, Some(|s| println!("{}", s))))
        .unwrap();
}
