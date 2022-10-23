use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use arrayref::array_ref;
use inwx::call::nameserver::{RecordInfo as RecordInfoCall, RecordUpdate};
use inwx::common::nameserver::RecordType;
use inwx::response::nameserver::RecordInfo as RecordInfoResponse;
use inwx::{Client, Endpoint};

#[derive(Clone, Copy, Debug)]
struct Config<'a> {
    user: &'a str,
    pass: &'a str,
    records4: &'a [i32],
    records6: &'a [i32],
    prefix_len: u32,
    link4: &'a str,
    link6: &'a str,
    interval4: Duration,
    interval6: Duration,
}

fn main() -> anyhow::Result<()> {
    let config = Config {
        user: "inwxclient",
        pass: "inwx1@client",
        records4: &[75506],
        records6: &[75503],
        prefix_len: 56,
        link4: "wlan0",
        link6: "wlan0",
        interval4: Duration::from_secs(30),
        interval6: Duration::from_secs(30),
    };

    let (tx4, rx4) = mpsc::channel();
    let (tx6, rx6) = mpsc::channel();

    let push4_thread = thread::spawn(move || {
        push4(config, rx4)?;
        Ok::<(), anyhow::Error>(())
    });
    let push6_thread = thread::spawn(move || {
        push6(config, rx6)?;
        Ok::<(), anyhow::Error>(())
    });

    let monitor4_thread = thread::spawn(move || {
        monitor4(config, tx4)?;
        Ok::<(), anyhow::Error>(())
    });
    let monitor6_thread = thread::spawn(move || {
        monitor6(config, tx6)?;
        Ok::<(), anyhow::Error>(())
    });

    push4_thread.join().unwrap()?;
    push6_thread.join().unwrap()?;

    monitor4_thread.join().unwrap()?;
    monitor6_thread.join().unwrap()?;

    Ok(())
}

fn check_for_addrs4(config: Config, tx: mpsc::Sender<Ipv4Addr>) -> anyhow::Result<Ipv4Addr> {
    let mut ipv4 = None;

    loop {
        let new_ipv4 = preferred_ip::get_ipv4_global(config.link4)?;

        if ipv4.is_none() || ipv4.unwrap() != new_ipv4 {
            tx.send(new_ipv4)?;
            ipv4 = Some(new_ipv4);
        }

        thread::sleep(config.interval4);
    }
}

fn check_for_addrs6(config: Config, tx: mpsc::Sender<Ipv6Addr>) -> anyhow::Result<Ipv6Addr> {
    let mut ipv6 = None;

    loop {
        let new_ipv6 = preferred_ip::get_ipv6_unicast_global(config.link6)?;

        if ipv6.is_none() || ipv6.unwrap() != new_ipv6 {
            tx.send(new_ipv6)?;
            ipv6 = Some(new_ipv6);
        }

        thread::sleep(config.interval6);
    }
}

fn monitor4(config: Config, tx: mpsc::Sender<Ipv4Addr>) -> anyhow::Result<()> {
    loop {
        match check_for_addrs4(config, tx.clone()) {
            Ok(_) => println!("check_for_addrs4 exited Ok (this is bad)"),
            Err(e) => println!("{}", e),
        }

        thread::sleep(config.interval4);
    }
}

fn monitor6(config: Config, tx: mpsc::Sender<Ipv6Addr>) -> anyhow::Result<()> {
    loop {
        match check_for_addrs6(config, tx.clone()) {
            Ok(_) => println!("check_for_addrs6 exited Ok (this is bad)"),
            Err(e) => println!("{}", e),
        }

        thread::sleep(config.interval6);
    }
}

fn push4(config: Config, rx: mpsc::Receiver<Ipv4Addr>) -> anyhow::Result<()> {
    let mut last_address = None;
    loop {
        let address = rx.recv()?;
        if last_address.is_none() || address != last_address.unwrap() {
            let clt = Client::login(Endpoint::Sandbox, config.user, config.pass)?;

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

fn push6(config: Config, rx: mpsc::Receiver<Ipv6Addr>) -> anyhow::Result<()> {
    let mut last_prefix = None;
    loop {
        let prefix = rx.recv()?;
        if last_prefix.is_none() || prefix != last_prefix.unwrap() {
            let clt = Client::login(Endpoint::Sandbox, config.user, config.pass)?;

            let mut total_records = Vec::new();
            for id in config.records6 {
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

                let b_addr = address.octets().to_vec();
                let b_net = prefix.octets().to_vec();

                let new_raw = change_prefix(b_addr, b_net, config.prefix_len);
                let new = Ipv6Addr::from(*array_ref!(new_raw.as_slice(), 0, 16));

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

fn change_prefix(address: Vec<u8>, prefix: Vec<u8>, bits: u32) -> Vec<u8> {
    address
        .iter()
        .zip(prefix.iter())
        .enumerate()
        .map(|(i, (a, b))| {
            if i as u32 >= bits / 8 {
                let ones = bits % 8;
                let mask = !(0xff_u8.overflowing_shr(ones).0);

                (a & !mask) | (b & mask)
            } else {
                *b
            }
        })
        .collect()
}
