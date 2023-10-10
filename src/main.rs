use std::env;
use std::fs::File;
use std::io;
use std::net::{self, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use inwx::call::nameserver::{RecordInfo as RecordInfoCall, RecordUpdate};
use inwx::response::nameserver::RecordInfo as RecordInfoResponse;
use inwx::{Client, Endpoint};
use ipnet::{IpBitAnd, IpBitOr, IpNet, Ipv6Net};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

const MAX_DNS_ATTEMPTS: usize = 3;

#[derive(Debug, Error)]
enum Error {
    #[error("inwx: {0}")]
    Inwx(#[from] inwx::Error),
    #[error("linkaddrs: {0}")]
    LinkAddrs(#[from] linkaddrs::Error),
    #[error("can't parse ip address: {0}")]
    ParseAddr(#[from] net::AddrParseError),
    #[error("prefix length error: {0}")]
    PrefixLen(#[from] ipnet::PrefixLenError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("trust_dns_resolver resolve error: {0}")]
    TrustDnsResolve(#[from] trust_dns_resolver::error::ResolveError),
    #[error("missing ipv6 record (id: {0})")]
    MissingRecord(i32),
    #[error("can't find endpoint hostname, this shouldn't happen")]
    NoHostname,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    ipv4: Option<ConfigIpv4>,
    ipv6: Option<ConfigIpv6>,
    net6: Option<ConfigNet6>,
    interval: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConfigIpv4 {
    user: String,
    pass: String,
    records: Vec<i32>,
    link: String,
    custom_dns: Option<SocketAddr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConfigIpv6 {
    user: String,
    pass: String,
    records: Vec<i32>,
    link: String,
    custom_dns: Option<SocketAddr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConfigNet6 {
    user: String,
    pass: String,
    records: Vec<i32>,
    len: u8,
    link: String,
    custom_dns: Option<SocketAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AddrState {
    addr4: Ipv4Addr,
    addr6: Ipv6Addr,
    net6: Ipv6Net,
}

impl AddrState {
    fn new() -> Self {
        Self {
            addr4: Ipv4Addr::UNSPECIFIED,
            addr6: Ipv6Addr::UNSPECIFIED,
            net6: Ipv6Net::default(),
        }
    }
}

fn main() -> Result<()> {
    // Get the config path from the first command-line argument
    // or fall back to the default /data/dyndns.conf.
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("/data/dyndns.conf"));

    let mut config_file = File::open(config_path.as_str())?;

    if config_file.metadata()?.permissions().mode() & 0o077 > 0 {
        println!("[warn] WARNING: insecure permissions on config");
    }

    let config: Config = serde_json::from_reader(&mut config_file)?;

    let mut state = AddrState::new();
    loop {
        match logic(&mut state, &config) {
            Ok(_) => {}
            Err(e) => eprintln!("[warn] {}", e),
        }

        thread::sleep(Duration::from_secs(config.interval));
    }
}

fn logic(state: &mut AddrState, config: &Config) -> Result<()> {
    if let Some(ref config) = config.ipv4 {
        logic_addr4(state, config)?;
    }
    if let Some(ref config) = config.ipv6 {
        logic_addr6(state, config)?;
    }
    if let Some(ref config) = config.net6 {
        logic_net6(state, config)?;
    }

    Ok(())
}

fn logic_addr4(state: &mut AddrState, config: &ConfigIpv4) -> Result<()> {
    if let Some(addr4) = linkaddrs::ipv4_addresses(config.link.clone())?
        .into_iter()
        .map(|net| net.addr())
        .find(is_ipv4_global)
    {
        if addr4 != state.addr4 {
            println!("[info] ipv4 {} => {}", state.addr4, addr4);

            let user = config.user.clone();
            let pass = config.pass.clone();

            #[cfg(not(debug_assertions))]
            let endpoint = Endpoint::Production;

            #[cfg(debug_assertions)]
            let endpoint = Endpoint::Sandbox;

            let clt = match config.custom_dns {
                Some(custom_dns) => {
                    let addr = resolve_endpoint(&endpoint, custom_dns)?;
                    Client::login_addr(endpoint, addr, user, pass)
                }
                None => Client::login(endpoint, user, pass),
            }?;

            clt.call(RecordUpdate {
                ids: config.records.clone(),
                record_type: Some("A".to_owned()),
                content: Some(addr4.to_string()),
                ttl: Some(300),
                ..Default::default()
            })?;

            state.addr4 = addr4;
        }
    }

    Ok(())
}

fn logic_addr6(state: &mut AddrState, config: &ConfigIpv6) -> Result<()> {
    if let Some(addr6) = linkaddrs::ipv6_addresses(config.link.clone())?
        .into_iter()
        .map(|net| net.addr())
        .find(is_ipv6_global)
    {
        if addr6 != state.addr6 {
            println!("[info] ipv6 {} => {}", state.addr6, addr6);

            let user = config.user.clone();
            let pass = config.pass.clone();

            #[cfg(not(debug_assertions))]
            let endpoint = Endpoint::Production;

            #[cfg(debug_assertions)]
            let endpoint = Endpoint::Sandbox;

            let clt = match config.custom_dns {
                Some(custom_dns) => {
                    let addr = resolve_endpoint(&endpoint, custom_dns)?;
                    Client::login_addr(endpoint, addr, user, pass)
                }
                None => Client::login(endpoint, user, pass),
            }?;

            clt.call(RecordUpdate {
                ids: config.records.clone(),
                record_type: Some("AAAA".to_owned()),
                content: Some(addr6.to_string()),
                ttl: Some(300),
                ..Default::default()
            })?;

            state.addr6 = addr6;
        }
    }

    Ok(())
}

fn logic_net6(state: &mut AddrState, config: &ConfigNet6) -> Result<()> {
    if let Some(net6) = linkaddrs::ipv6_addresses(config.link.clone())?
        .into_iter()
        .find(|net| is_ipv6_global(&net.addr()))
    {
        // Resize the prefix.
        let net6 = Ipv6Net::new(net6.addr(), config.len)?.trunc();

        if net6 != state.net6 {
            println!("[info] net6 {} => {}", state.net6, net6);

            let user = config.user.clone();
            let pass = config.pass.clone();

            #[cfg(not(debug_assertions))]
            let endpoint = Endpoint::Production;

            #[cfg(debug_assertions)]
            let endpoint = Endpoint::Sandbox;

            let clt = match config.custom_dns {
                Some(custom_dns) => {
                    let addr = resolve_endpoint(&endpoint, custom_dns)?;
                    Client::login_addr(endpoint, addr, user, pass)
                }
                None => Client::login(endpoint, user, pass),
            }?;

            for record_id in &config.records {
                let info: RecordInfoResponse = clt.call(RecordInfoCall {
                    record_id: Some(*record_id),
                    record_type: Some("AAAA".to_owned()),
                    ..Default::default()
                })?;

                let records = info.records.ok_or(Error::MissingRecord(*record_id))?;
                let record = records.first().ok_or(Error::MissingRecord(*record_id))?;

                let address = Ipv6Addr::from_str(&record.content)?;

                // Get the interface identifier and append it to the new prefix.
                let if_id = address.bitand(net6.hostmask());
                let new = net6.addr().bitor(if_id);

                clt.call(RecordUpdate {
                    ids: vec![record.id],
                    record_type: Some("AAAA".to_owned()),
                    content: Some(new.to_string()),
                    ttl: Some(300),
                    ..Default::default()
                })?;
            }

            state.net6 = net6;
        }
    }

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

fn resolve_endpoint(endpoint: &Endpoint, custom_dns: SocketAddr) -> Result<SocketAddr> {
    for i in 0..MAX_DNS_ATTEMPTS {
        match resolve_custom_dns(endpoint.domain(), custom_dns) {
            Ok(ip_addr) => return Ok((ip_addr, 443).into()),
            Err(e) => {
                if i >= MAX_DNS_ATTEMPTS - 1 {
                    return Err(e);
                } else {
                    eprintln!("{}", e);
                }
            }
        }

        thread::sleep(Duration::from_secs(8));
    }

    unreachable!()
}

fn resolve_custom_dns(hostname: &str, custom_dns: SocketAddr) -> Result<IpAddr> {
    let mut cfg = ResolverConfig::new();

    cfg.add_name_server(NameServerConfig::new(custom_dns, Protocol::Udp));

    let resolver = Resolver::new(cfg, ResolverOpts::default())?;
    let response = resolver.lookup_ip(hostname)?;

    let ip_addr = response.iter().next().ok_or(Error::NoHostname)?;
    Ok(ip_addr)
}
