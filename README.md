# dyndns

A dynamic DNS client using the INWX XML-RPC API, written in Rust.

This client uses the official XML-RPC API instead of the DynDNS API.
As a result there is no limit on the number of DynDNS records.

It only works if you're using INWX's own nameservers for your zone.

# Usage

```
dyndns [config]
```

where config is the config path (defaults to /data/dyndns.conf).

# Configuration

The configuration file is simply a JSON file.

**Since this file contains account credentials the client will print a warning
if anyone other than its owner has any permissions.
A reasonable default is 0600.**

Unfortunately INWX does not support API tokens.

*Two-factor authentication is currently not supported by this program.
Feel free to contribute.*

## Getting your record IDs

Open the INWX web panel and create the records if you haven't already.
Make sure to use the correct record type.

Then, inspect the grey row of the record using the developer tools.
It should be a div with an ID formatted like this: `record_div_X`.
The number X is the record ID.

## Basic Config Example

```
{
	"ipv4": {
		"user": "INWX_ACCOUNT_NAME",
		"pass": "INWX_ACCOUNT_PASSWD",
		"records": [1, 2, 4],
		"link": "ROUTER_WAN_INTERFACE",
		"interval": 300,
		"retry": 30
	},
	"ipv6": {
		"user": "INWX_ACCOUNT_NAME",
		"pass": "INWX_ACCOUNT_PASSWD",
		"records": [8, 16, 32],
		"link": "ROUTER_WAN_INTERFACE",
		"interval": 300,
		"retry": 30
	}
}
```

The `ipv4` and `ipv6` subsections work in the same way.
They push the global IP address of the network interface (link)
to all records from the list.
If multiple global addresses are present, a random one is selected.

The client checks for address updates every 300 seconds (5 minutes, can be changed).
The retry interval is optional. If the address update check or API call fails,
the client will make infinite attempts at this interval.
It defaults to the regular interval if unspecified.

*You do not need to initialize the records to a specific value.
Initializing to `0.0.0.0` or `::` is sufficient.*

## Prefix Config Example

This client includes a special feature: It can update the prefix of your server machines
without you having to run DDNS client software on each server.
It does this by swapping the prefixes while leaving the interface identifiers
of your machines untouched.

Ideally this program would directly interface with the router's DHCPv6 client.
Right now it simply reads a LAN side IPv6 address of the router and truncates
everything beyond the prefix length.

### Getting your prefix length

Do some research on the internet to find out which prefix length you get
from your ISP or look it up in your router web panel if it supports it.
Common lengths include /64, /60, /59, /56 and /48.
From my experience /56 is the most common prefix length for residential customers.
If you aren't sure, /64 is a relatively safe option that should work
in most single-subnet LANs.

```
{
	"net6": {
		"user": "INWX_ACCOUNT_NAME",
		"pass": "INWX_ACCOUNT_PASSWD",
		"records": [64, 128, 256],
		"len": 56,
		"link": "ROUTER_PRIMARY_LAN_INTERFACE",
		"interval": 300,
		"retry": 30
	}
}
```

*Unlike with the basic config the records have to be initialized
with the correct interface identifiers. You can use any prefix,
but I recommend to just set it to all-zero. Example: `::abcd`.*

Do note that you can merge this with the basic config
if you want router connectivity via DynDNS.

# OpenWrt

## Cross compilation

Install [cross](https://crates.io/crates/cross):

```
cargo install cross
```

Then, install the correct target: *<ARCHITECTURE>-unknown-linux-musl*

Example (aarch64):

```
rustup target add aarch64-unknown-linux-musl
```

You are now ready to cross-compile:

```
cross build --release --target aarch64-unknown-linux-musl
```

The resulting binary can be found at `target/<TARGET>/release/dyndns`
and run on OpenWrt.

## Init script

The script below can also be found in [dyndns.rc](https://github.com/HimbeerserverDE/dyndns-rs/blob/master/dyndns.rc).
This is a simple OpenWrt init script to automatically start the client:

```
#!/bin/sh /etc/rc.common
#
# chkconfig: 35 99 15
# description: DynDNS (Rust)
#

START=99
STOP=15

start() {
	echo "Starting dyndns-rs" | logger -p daemon.info -t dyndns
	(/usr/bin/dyndns | logger -p daemon.info -t dyndns) &

	touch /var/lock/procd_dyndns.lock
	echo "dyndns-rs startup" | logger -p daemon.info -t dyndns
}

stop() {
	echo "Stopping dyndns-rs" | logger -p daemon.info -t dyndns
	killall dyndns

	rm -f /var/lock/procd_dyndns.lock
}
```

Put this in `/etc/init.d/dyndns` and add execution permissions.
The `dyndns` binary must be located at `/usr/bin/dyndns`.

**This will run the client as root, which undermines multi-user
security advantages.**

## Config

Config is the same, but be sure to use the hardware interface names.
The logical interfaces names (e.g. "WAN6") won't work.
