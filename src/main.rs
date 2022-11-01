use std::env;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use inwx::call::nameserver::{RecordInfo as RecordInfoCall, RecordUpdate};
use inwx::common::nameserver::RecordType;
use inwx::response::nameserver::RecordInfo as RecordInfoResponse;
use inwx::{Client, Endpoint};
use ipnet::{IpBitAnd, IpBitOr, IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
enum Error {
    ChannelRecv(mpsc::RecvError),
    ChannelSend4(mpsc::SendError<Ipv4Net>),
    ChannelSend6(mpsc::SendError<Ipv6Net>),
    Inwx(inwx::Error),
    LinkAddrs(linkaddrs::Error),
    ParseAddr(std::net::AddrParseError),
    PrefixLen(ipnet::PrefixLenError),
    Io(std::io::Error),
    SerdeJson(serde_json::Error),
    MissingRecord(i32),
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelRecv(e) => write!(fmt, "can't recv from mpsc channel: {}", e),
            Self::ChannelSend4(e) => write!(fmt, "can't send to mpsc channel: {}", e),
            Self::ChannelSend6(e) => write!(fmt, "can't send to mpsc channel: {}", e),
            Self::Inwx(e) => write!(fmt, "inwx library error: {}", e),
            Self::LinkAddrs(e) => write!(fmt, "linkaddrs library error: {}", e),
            Self::ParseAddr(e) => write!(fmt, "can't parse ip address: {}", e),
            Self::PrefixLen(e) => write!(fmt, "prefix length error: {}", e),
            Self::Io(e) => write!(fmt, "io error: {}", e),
            Self::SerdeJson(e) => write!(fmt, "serde_json library error: {}", e),
            Self::MissingRecord(id) => write!(fmt, "missing ipv6 record (id: {})", id),
        }
    }
}

impl From<mpsc::RecvError> for Error {
    fn from(e: mpsc::RecvError) -> Self {
        Self::ChannelRecv(e)
    }
}

impl From<mpsc::SendError<Ipv4Net>> for Error {
    fn from(e: mpsc::SendError<Ipv4Net>) -> Self {
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

impl From<linkaddrs::Error> for Error {
    fn from(e: linkaddrs::Error) -> Self {
        Self::LinkAddrs(e)
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

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeJson(e)
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    user: String,
    pass: String,
    records_addr4: Vec<i32>,
    records_addr6: Vec<i32>,
    records_net6: Vec<i32>,
    prefix_len: u8,
    link_wan4: String,
    link_wan6: String,
    link_lan6: String,
    interval4: u64,
    interval6: u64,
}

fn main() -> Result<()> {
    // Get the config path from the first command-line argument
    // or fall back to the default /etc/dyndns.conf.
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("/etc/dyndns.conf"));

    let mut config_file = File::open(config_path.as_str())?;

    let mut config_contents = String::new();
    config_file.read_to_string(&mut config_contents).unwrap();

    let parsed_config: Config = serde_json::from_str(&config_contents)?;
    let config = Arc::new(parsed_config);

    let config0 = config.clone();
    let config1 = config.clone();
    let config2 = config.clone();
    let config3 = config.clone();
    let config4 = config.clone();
    let config5 = config;

    let (tx_addr4, rx_addr4) = mpsc::channel();
    let (tx_addr6, rx_addr6) = mpsc::channel();
    let (tx_net6, rx_net6) = mpsc::channel();

    let push_addr4_thread = thread::spawn(move || {
        loop {
            match push_addr4(config0.clone(), &rx_addr4) {
                Ok(_) => { /* unreachable */ }
                Err(e) => eprintln!("failed to push ipv4 address: {}", e),
            }

            thread::sleep(Duration::from_secs(config0.interval4));
        }
    });
    let push_addr6_thread = thread::spawn(move || {
        loop {
            match push_addr6(config1.clone(), &rx_addr6) {
                Ok(_) => { /* unreachable */ }
                Err(e) => eprintln!("failed to push ipv6 address: {}", e),
            }

            thread::sleep(Duration::from_secs(config1.interval6));
        }
    });
    let push_net6_thread = thread::spawn(move || {
        loop {
            match push_net6(config2.clone(), &rx_net6) {
                Ok(_) => { /* unreachable */ }
                Err(e) => eprintln!("failed to push ipv6 prefix: {}", e),
            }

            thread::sleep(Duration::from_secs(config2.interval6));
        }
    });

    let monitor_addr4_thread = thread::spawn(move || {
        loop {
            match monitor_addr4(config3.clone(), tx_addr4.clone()) {
                Ok(_) => { /* unreachable */ }
                Err(e) => eprintln!("failed to monitor ipv4 address: {}", e),
            }

            thread::sleep(Duration::from_secs(config3.interval4));
        }
    });
    let monitor_addr6_thread = thread::spawn(move || {
        loop {
            match monitor_addr6(config4.clone(), tx_addr6.clone()) {
                Ok(_) => { /* unreachable */ }
                Err(e) => eprintln!("failed to monitor ipv6 address: {}", e),
            }

            thread::sleep(Duration::from_secs(config4.interval6));
        }
    });
    let monitor_net6_thread = thread::spawn(move || {
        loop {
            match monitor_net6(config5.clone(), tx_net6.clone()) {
                Ok(_) => { /* unreachable */ }
                Err(e) => eprintln!("failed to monitor ipv6 prefix: {}", e),
            }

            thread::sleep(Duration::from_secs(config5.interval6));
        }
    });

    push_addr4_thread.join().unwrap();
    push_addr6_thread.join().unwrap();
    push_net6_thread.join().unwrap();

    monitor_addr4_thread.join().unwrap();
    monitor_addr6_thread.join().unwrap();
    monitor_net6_thread.join().unwrap();

    Ok(())
}

// Convenience wrapper.
fn net_contains(net_str: &str, addr: &IpAddr) -> bool {
    net_str.parse::<IpNet>().unwrap().contains(addr)
}

fn is_ipv4_global(addr: &Ipv4Addr) -> bool {
    let addr = (*addr).into();

    !net_contains("0.0.0.0/8", &addr)
        && !net_contains("10.0.0.0/8", &addr)
        && !net_contains("127.0.0.0/8", &addr)
        && !net_contains("169.254.0.0/16", &addr)
        && !net_contains("172.16.0.0/12", &addr)
        && !net_contains("192.0.0.0/24", &addr)
        && !net_contains("192.0.2.0/24", &addr)
        && !net_contains("192.88.99.0/24", &addr)
        && !net_contains("192.168.0.0/16", &addr)
        && !net_contains("198.18.0.0/15", &addr)
        && !net_contains("198.51.100.0/24", &addr)
        && !net_contains("203.0.113.0/24", &addr)
        && !net_contains("224.0.0.0/4", &addr)
        && !net_contains("240.0.0.0/4", &addr)
        && !net_contains("255.255.255.255/32", &addr)
}

fn is_ipv6_global(addr: &Ipv6Addr) -> bool {
    let addr = (*addr).into();

    !net_contains("::1/128", &addr)
        && !net_contains("::/128", &addr)
        && !net_contains("::ffff:0:0/96", &addr)
        && !net_contains("::/96", &addr)
        && !net_contains("fe80::/10", &addr)
        && !net_contains("fc00::/7", &addr)
        && !net_contains("2001:db8::/32", &addr)
        && !net_contains("5f00::/8", &addr)
        && !net_contains("3ffe::/16", &addr)
        && !net_contains("2001:10::/28", &addr)
        && !net_contains("ff00::/8", &addr)
}

fn monitor_addr4(config: Arc<Config>, tx: mpsc::Sender<Ipv4Net>) -> Result<()> {
    let mut ipv4 = None;

    loop {
        let ipv4s = linkaddrs::ipv4_addresses(config.link_wan4.clone())?;

        for newv4 in ipv4s {
            if is_ipv4_global(&newv4.addr()) && (ipv4.is_none() || ipv4.unwrap() != newv4) {
                if let Some(ipv4) = ipv4 {
                    println!("ipv4 update: {} => {}", ipv4, newv4);
                } else {
                    println!("ipv4: {}", newv4);
                }

                tx.send(newv4)?;
                ipv4 = Some(newv4);

                break;
            }
        }

        thread::sleep(Duration::from_secs(config.interval4));
    }
}

fn monitor_addr6(config: Arc<Config>, tx: mpsc::Sender<Ipv6Net>) -> Result<()> {
    let mut ipv6 = None;

    loop {
        let ipv6s = linkaddrs::ipv6_addresses(config.link_wan6.clone())?;

        for newv6 in ipv6s {
            if is_ipv6_global(&newv6.addr()) && (ipv6.is_none() || ipv6.unwrap() != newv6) {
                if let Some(ipv6) = ipv6 {
                    println!("ipv6 update: {} => {}", ipv6, newv6);
                } else {
                    println!("ipv6: {}", newv6);
                }

                tx.send(newv6)?;
                ipv6 = Some(newv6);

                break;
            }
        }

        thread::sleep(Duration::from_secs(config.interval6));
    }
}

fn monitor_net6(config: Arc<Config>, tx: mpsc::Sender<Ipv6Net>) -> Result<()> {
    let mut ipv6 = None;

    loop {
        let ipv6s = linkaddrs::ipv6_addresses(config.link_lan6.clone())?;

        for newv6 in ipv6s {
            // Resize the prefix.
            let prefix = Ipv6Net::new(newv6.addr(), config.prefix_len)?.trunc();

            if is_ipv6_global(&prefix.addr()) && (ipv6.is_none() || ipv6.unwrap() != prefix) {
                if let Some(ipv6) = ipv6 {
                    println!("ipv6 prefix update: {} => {}", ipv6, prefix);
                } else {
                    println!("ipv6 prefix: {}", prefix);
                }

                tx.send(prefix)?;
                ipv6 = Some(prefix);

                break;
            }
        }

        thread::sleep(Duration::from_secs(config.interval6));
    }
}

fn push_addr4(config: Arc<Config>, rx: &mpsc::Receiver<Ipv4Net>) -> Result<()> {
    loop {
        let address = rx.recv()?;

        let user = config.user.clone();
        let pass = config.pass.clone();

        let clt = Client::login(Endpoint::Sandbox, user, pass)?;

        clt.call(RecordUpdate {
            ids: config.records_addr4.clone(),
            name: None,
            record_type: Some(RecordType::A),
            content: Some(address.addr().to_string()),
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
}

fn push_addr6(config: Arc<Config>, rx: &mpsc::Receiver<Ipv6Net>) -> Result<()> {
    loop {
        let address = rx.recv()?;

        let user = config.user.clone();
        let pass = config.pass.clone();

        let clt = Client::login(Endpoint::Sandbox, user, pass)?;

        clt.call(RecordUpdate {
            ids: config.records_addr6.clone(),
            name: None,
            record_type: Some(RecordType::Aaaa),
            content: Some(address.addr().to_string()),
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
}

fn push_net6(config: Arc<Config>, rx: &mpsc::Receiver<Ipv6Net>) -> Result<()> {
    loop {
        let prefix = rx.recv()?;

        let user = config.user.clone();
        let pass = config.pass.clone();

        let clt = Client::login(Endpoint::Sandbox, user, pass)?;

        for id in &config.records_net6 {
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

            let records = info.records.ok_or(Error::MissingRecord(*id))?;
            let record = records.first().ok_or(Error::MissingRecord(*id))?;

            let address = Ipv6Addr::from_str(&record.content)?;

            // Get the interface identifier and append it to the new prefix.
            let if_id = address.bitand(prefix.hostmask());
            let new = prefix.addr().bitor(if_id);

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
    }
}
