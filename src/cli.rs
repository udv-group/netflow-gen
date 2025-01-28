use std::error::Error;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::ops::RangeInclusive;

use clap::{Args, Parser};

use crate::gen::{NetAddr, Protocol};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Adress of the Collector
    #[arg(short, long)]
    pub address: Ipv4Addr,

    /// Port of the Collector
    #[arg(short, long, default_value_t = 9995)]
    pub port: u16,

    /// Messages per second
    #[arg(short, long)]
    pub rate: NonZeroU32,

    #[command(flatten)]
    pub src: Source,

    #[command(flatten)]
    pub dst: Destination,

    #[arg(long, default_value_t = Protocol::TCP, value_parser=parse_protocol)]
    pub protocol: Protocol,

    #[command(flatten)]
    pub templates: TemplateSyncStrategy,
}

#[derive(Args, Debug)]
pub struct Source {
    #[command(flatten)]
    pub ip: SrcAddr,

    #[command(flatten)]
    pub ports: SrcPort,

    /// Source MAC address of the flow
    #[arg(id="SRC_MAC_ADDRESS", long="src-mac", default_value="00:00:00:00:00:00", value_parser = parse_mac)]
    pub mac: [u8; 6],
}

#[derive(Args, Debug)]
pub struct Destination {
    #[command(flatten)]
    pub ip: DstAddr,

    #[command(flatten)]
    pub ports: DstPort,

    /// Destination MAC address of the flow
    #[arg(id="DST_MAC_ADDRESS", long="dst-mac", default_value="00:00:00:00:00:00", value_parser = parse_mac)]
    pub mac: [u8; 6],
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct SrcAddr {
    /// IP address of the flow source
    #[arg(id = "SRC_ADDRESS", long = "src-addr")]
    pub address: Option<Ipv4Addr>,

    /// IP subnet from wich flow source address will be selected
    #[arg(id = "SRC_SUBNET", long = "src-subnet")]
    pub subnet: Option<ipnet::Ipv4Net>,
}

impl From<SrcAddr> for NetAddr {
    fn from(val: SrcAddr) -> Self {
        val.address
            .map(|d| d.into())
            .unwrap_or_else(|| val.subnet.unwrap().into())
    }
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct DstAddr {
    /// IP address of the flow destination
    #[arg(id = "DST_ADDRESS", long = "dst-addr")]
    pub address: Option<Ipv4Addr>,

    /// IP subnet from wich flow destination address will be selected
    #[arg(id = "DST_SUBNET", long = "dst-subnet")]
    pub subnet: Option<ipnet::Ipv4Net>,
}

impl From<DstAddr> for NetAddr {
    fn from(val: DstAddr) -> Self {
        val.address
            .map(|d| d.into())
            .unwrap_or_else(|| val.subnet.unwrap().into())
    }
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct SrcPort {
    /// Source port of a flow
    #[arg(id = "SRC_PORT", long = "src-port")]
    pub port: Option<u16>,

    /// Range of ports to select source port for a flow
    #[arg(id="SRC_PORT_RANGE",long="src-port-range", value_parser = parse_port_range)]
    pub port_range: Option<RangeInclusive<u16>>,
}

impl From<SrcPort> for RangeInclusive<u16> {
    fn from(val: SrcPort) -> Self {
        val.port_range
            .unwrap_or_else(|| val.port.map(|p| p..=p).unwrap())
    }
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct DstPort {
    /// Destination port of a flow
    #[arg(id = "DST_PORT", long = "dst-port")]
    pub port: Option<u16>,

    /// Range of ports to select destination port for a flow
    #[arg(id="DST_PORT_RANGE",long="dst-port-range", value_parser = parse_port_range)]
    pub port_range: Option<RangeInclusive<u16>>,
}

impl From<DstPort> for RangeInclusive<u16> {
    fn from(val: DstPort) -> Self {
        val.port_range
            .unwrap_or_else(|| val.port.map(|p| p..=p).unwrap())
    }
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct TemplateSyncStrategy {
    /// Send template in the first packet and only once
    #[arg(long)]
    pub once: bool,

    /// Send templates together with data in the same packet
    #[arg(long)]
    pub interleve: bool,

    /// Send templates in separate packet every <EVERY> packets
    #[arg(long)]
    pub every: Option<u32>,
}

fn parse_mac(s: &str) -> Result<[u8; 6], Box<dyn Error + Send + Sync + 'static>> {
    let mut array = [0u8; 6];

    let mut nth = 0;
    for byte in s.split([':', '-']) {
        if nth == 6 {
            return Err("Invalid MAC address length".into());
        }

        array[nth] = u8::from_str_radix(byte, 16)
            .map_err(|e| format!("Incorrect value for MAC adress: {}", e))?;

        nth += 1;
    }

    if nth != 6 {
        return Err("Invalid MAC address length".into());
    };
    Ok(array)
}

fn parse_port_range(
    s: &str,
) -> Result<RangeInclusive<u16>, Box<dyn Error + Send + Sync + 'static>> {
    let ports: Vec<&str> = s.split(',').collect();
    if ports.len() != 2 {
        return Err("Invalid port range specification. Should be <start>,<end>".into());
    }
    Ok(ports[0].parse()?..=ports[1].parse()?)
}

fn parse_protocol(s: &str) -> Result<Protocol, Box<dyn Error + Send + Sync + 'static>> {
    s.try_into().map_err(|e: String| e.into())
}
