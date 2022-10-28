use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use inwx::call::nameserver::{RecordInfo as RecordInfoCall, RecordUpdate};
use inwx::common::nameserver::RecordType;
use inwx::response::nameserver::RecordInfo as RecordInfoResponse;
use inwx::{Client, Endpoint};
use ipnet::{IpBitAnd, IpBitOr, Ipv6Net};

#[derive(Debug)]
enum Error {
    ChannelRecv(mpsc::RecvError),
    ChannelSend4(mpsc::SendError<Ipv4Addr>),
    ChannelSend6(mpsc::SendError<Ipv6Net>),
    Inwx(inwx::Error),
    PreferredIp(preferred_ip::Error),
    ParseAddr(std::net::AddrParseError),
    PrefixLen(ipnet::PrefixLenError),
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelRecv(e) => write!(fmt, "can't recv from mpsc channel: {}", e),
            Self::ChannelSend4(e) => write!(fmt, "can't send to mpsc channel: {}", e),
            Self::ChannelSend6(e) => write!(fmt, "can't send to mpsc channel: {}", e),
            Self::Inwx(e) => write!(fmt, "inwx library error: {}", e),
            Self::PreferredIp(e) => write!(fmt, "preferred_ip library error: {}", e),
            Self::ParseAddr(e) => write!(fmt, "can't parse ip address: {}", e),
            Self::PrefixLen(e) => write!(fmt, "prefix length error: {}", e),
        }
    }
}

impl From<mpsc::RecvError> for Error {
    fn from(e: mpsc::RecvError) -> Self {
        Self::ChannelRecv(e)
    }
}

impl From<mpsc::SendError<Ipv4Addr>> for Error {
    fn from(e: mpsc::SendError<Ipv4Addr>) -> Self {
        Self::ChannelSend4(e)
    }
}

impl From<mpsc::SendError<Ipv6Net>> for Error {
    fn from(e: mpsc::SendError<Ipv6Net>) -> Self {
        Self::ChannelSend6(e)
    }
}

impl From<inwx::Error> for Error {
    fn from(e: inwx::Error) -> Self {
        Self::Inwx(e)
    }
}

impl From<preferred_ip::Error> for Error {
    fn from(e: preferred_ip::Error) -> Self {
        Self::PreferredIp(e)
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(e: std::net::AddrParseError) -> Self {
        Self::ParseAddr(e)
    }
}

impl From<ipnet::PrefixLenError> for Error {
    fn from(e: ipnet::PrefixLenError) -> Self {
        Self::PrefixLen(e)
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
struct Config {
    user: String,
    pass: String,
    records4: Vec<i32>,
    records6: Vec<i32>,
    prefix_len: u8,
    link4: String,
    link6: String,
    interval4: Duration,
    interval6: Duration,
}

fn main() -> Result<()> {
    let config = Arc::new(Config {
        user: String::from("inwxclient"),
        pass: String::from("inwx1@client"),
        records4: vec![75506],
        records6: vec![75503],
        prefix_len: 56,
        link4: String::from("eth0"),
        link6: String::from("eth0"),
        interval4: Duration::from_secs(30),
        interval6: Duration::from_secs(30),
    });

    let config0 = config.clone();
    let config1 = config.clone();
    let config2 = config.clone();
    let config3 = config;

    let (tx4, rx4) = mpsc::channel();
    let (tx6, rx6) = mpsc::channel();

    let push4_thread = thread::spawn(move || {
        loop {
            match push4(config0.clone(), &rx4) {
                Ok(_) => { /* unreachable */ }
                Err(e) => println!("failed to push ipv4 address: {}", e),
            }

            thread::sleep(config0.interval4);
        }
    });
    let push6_thread = thread::spawn(move || {
        loop {
            match push6(config1.clone(), &rx6) {
                Ok(_) => { /* unreachable */ }
                Err(e) => println!("failed to push ipv6 prefix: {}", e),
            }

            thread::sleep(config1.interval6);
        }
    });

    let monitor4_thread = thread::spawn(move || {
        loop {
            match monitor4(config2.clone(), tx4.clone()) {
                Ok(_) => { /* unreachable */ }
                Err(e) => println!("failed to monitor ipv4 address: {}", e),
            }

            thread::sleep(config2.interval4);
        }
    });
    let monitor6_thread = thread::spawn(move || {
        loop {
            match monitor6(config3.clone(), tx6.clone()) {
                Ok(_) => { /* unreachable */ }
                Err(e) => println!("failed to monitor ipv6 prefix: {}", e),
            }

            thread::sleep(config3.interval6);
        }
    });

    push4_thread.join().unwrap();
    push6_thread.join().unwrap();

    monitor4_thread.join().unwrap();
    monitor6_thread.join().unwrap();

    Ok(())
}

fn monitor4(config: Arc<Config>, tx: mpsc::Sender<Ipv4Addr>) -> Result<()> {
    let mut ipv4 = None;

    loop {
        let new_ipv4 = preferred_ip::ipv4_global(&config.link4)?;

        if ipv4.is_none() || ipv4.unwrap() != new_ipv4 {
            tx.send(new_ipv4)?;
            ipv4 = Some(new_ipv4);
        }

        thread::sleep(config.interval4);
    }
}

fn monitor6(config: Arc<Config>, tx: mpsc::Sender<Ipv6Net>) -> Result<()> {
    let mut ipv6 = None;

    loop {
        let new_ipv6 = preferred_ip::ipv6_unicast_global(&config.link6)?;

        if ipv6.is_none() || ipv6.unwrap() != new_ipv6 {
            tx.send(Ipv6Net::new(new_ipv6, config.prefix_len)?)?;
            ipv6 = Some(new_ipv6);
        }

        thread::sleep(config.interval6);
    }
}

fn push4(config: Arc<Config>, rx: &mpsc::Receiver<Ipv4Addr>) -> Result<()> {
    let mut last_address = None;
    loop {
        let address = rx.recv()?;
        if last_address.is_none() || address != last_address.unwrap() {
            let clt = Client::login(Endpoint::Sandbox, &config.user, &config.pass)?;

            clt.call(RecordUpdate {
                ids: config.records4.to_vec(),
                name: None,
                record_type: Some(RecordType::A),
                content: Some(address.to_string()),
                ttl: Some(300),
                priority: None,
                url_rdr_type: None,
                url_rdr_title: None,
                url_rdr_desc: None,
                url_rdr_keywords: None,
                url_rdr_favicon: None,
                url_append: None,
                testing_mode: false,
            })?;

            last_address = Some(address);
        }
    }
}

fn push6(config: Arc<Config>, rx: &mpsc::Receiver<Ipv6Net>) -> Result<()> {
    let mut last_prefix = None;
    loop {
        let prefix = rx.recv()?;
        if last_prefix.is_none() || prefix != last_prefix.unwrap() {
            let clt = Client::login(Endpoint::Sandbox, &config.user, &config.pass)?;

            let mut total_records = Vec::new();
            for id in &config.records6 {
                let info: RecordInfoResponse = clt
                    .call(RecordInfoCall {
                        domain_name: None,
                        domain_id: None,
                        record_id: Some(*id),
                        record_type: Some(RecordType::Aaaa),
                        name: None,
                        content: None,
                        ttl: None,
                        priority: None,
                    })?
                    .try_into()?;

                let mut records = info
                    .records
                    .expect("no AAAA records (this should never happen");

                total_records.append(&mut records);
            }

            for record in total_records {
                let address = Ipv6Addr::from_str(&record.content)?;

                // Get the interface identifier.
                let if_id = address.bitand(prefix.hostmask());
                let clean_prefix = prefix.addr().bitand(prefix.netmask());
                let new = clean_prefix.bitor(if_id);

                clt.call(RecordUpdate {
                    ids: vec![record.id],
                    name: None,
                    record_type: Some(RecordType::Aaaa),
                    content: Some(new.to_string()),
                    ttl: Some(300),
                    priority: None,
                    url_rdr_type: None,
                    url_rdr_title: None,
                    url_rdr_desc: None,
                    url_rdr_keywords: None,
                    url_rdr_favicon: None,
                    url_append: None,
                    testing_mode: false,
                })?;
            }

            last_prefix = Some(prefix);
        }
    }
}
