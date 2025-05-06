use chrono::Utc;
use core::ops::RangeInclusive;
use ipnet::Ipv4Net;
use std::{collections::HashMap, fmt::Display};

use netgauze_flow_pkt::{
    ie,
    netflow::{DataRecord, DecodingTemplate, NetFlowV9Packet, Set, TemplateRecord, TemplatesMap},
    DataSetId, FieldSpecifier,
};
use rand::rngs::ThreadRng;
use rand::seq::IteratorRandom;
use std::net::Ipv4Addr;
use sysinfo::System;

pub enum NetAddr {
    Subnet(Ipv4Net),
    Address(Ipv4Addr),
}

impl From<Ipv4Addr> for NetAddr {
    fn from(value: Ipv4Addr) -> Self {
        Self::Address(value)
    }
}
impl From<Ipv4Net> for NetAddr {
    fn from(value: Ipv4Net) -> Self {
        Self::Subnet(value)
    }
}

impl NetAddr {
    pub fn get_one(&self, rng: &mut ThreadRng) -> Ipv4Addr {
        match self {
            NetAddr::Address(addr) => *addr,
            NetAddr::Subnet(net) => net.hosts().choose(rng).expect("Network without any hosts"),
        }
    }
}

pub struct Interleve;
pub struct Once;
pub struct Every(u32);

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    TCP = 6,
    ICMP = 1,
}
impl From<Protocol> for ie::protocolIdentifier {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::TCP => ie::protocolIdentifier::TCP,
            Protocol::ICMP => ie::protocolIdentifier::ICMP,
        }
    }
}
impl TryFrom<&str> for Protocol {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "ICMP" => Ok(Protocol::ICMP),
            "TCP" => Ok(Protocol::TCP),
            v => Err(format!("Unsuported protocol variant {}", v)),
        }
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Protocol::ICMP => "ICMP",
            Protocol::TCP => "TCP",
        };
        f.write_str(s)
    }
}

pub struct NetFlowGenBuilder {
    src: NetAddr,
    dst: NetAddr,
    src_ports: RangeInclusive<u16>,
    dst_ports: RangeInclusive<u16>,
    protocol: Protocol,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
}

impl Default for NetFlowGenBuilder {
    fn default() -> Self {
        Self {
            src: NetAddr::Address("70.1.135.1".parse().unwrap()),
            dst: NetAddr::Address("70.1.135.2".parse().unwrap()),
            src_ports: 42069..=42069,
            dst_ports: 6969..=6969,
            protocol: Protocol::TCP,
            src_mac: [0, 0, 0, 0, 0, 0],
            dst_mac: [0, 0, 0, 0, 0, 0],
        }
    }
}

impl NetFlowGenBuilder {
    pub fn with_src_ip(mut self, src: NetAddr) -> Self {
        self.src = src;
        self
    }
    pub fn with_dst_ip(mut self, dst: NetAddr) -> Self {
        self.dst = dst;
        self
    }
    pub fn with_src_ports(mut self, range: RangeInclusive<u16>) -> Self {
        self.src_ports = range;
        self
    }
    pub fn with_dst_ports(mut self, range: RangeInclusive<u16>) -> Self {
        self.dst_ports = range;
        self
    }
    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }
    pub fn with_src_mac(mut self, mac: [u8; 6]) -> Self {
        self.src_mac = mac;
        self
    }
    pub fn with_dst_mac(mut self, mac: [u8; 6]) -> Self {
        self.dst_mac = mac;
        self
    }
    pub fn send_template_once(self, template_id: u16) -> (TemplatesMap, NetFlowGenerator<Once>) {
        self.build(template_id, Once)
    }
    pub fn send_template_every(
        self,
        template_id: u16,
        every: u32,
    ) -> (TemplatesMap, NetFlowGenerator<Every>) {
        self.build(template_id, Every(every))
    }
    pub fn send_template_with_data(
        self,
        template_id: u16,
    ) -> (TemplatesMap, NetFlowGenerator<Interleve>) {
        self.build(template_id, Interleve)
    }
    fn build<T>(self, template_id: u16, strat: T) -> (TemplatesMap, NetFlowGenerator<T>) {
        let field_specifiers = vec![
            FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
            FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
            FieldSpecifier::new(ie::IE::sourceTransportPort, 2).unwrap(),
            FieldSpecifier::new(ie::IE::destinationTransportPort, 2).unwrap(),
            FieldSpecifier::new(ie::IE::sourceMacAddress, 6).unwrap(),
            FieldSpecifier::new(ie::IE::destinationMacAddress, 6).unwrap(),
            FieldSpecifier::new(ie::IE::protocolIdentifier, 1).unwrap(),
        ];
        let scope_filed_specifiers = vec![];

        let templates_map: TemplatesMap = HashMap::from([(
            template_id,
            DecodingTemplate::new(
                scope_filed_specifiers.into(),
                field_specifiers.clone().into(),
            ),
        )]);

        let gen = NetFlowGenerator {
            src: self.src,
            dst: self.dst,
            src_port: self.src_ports,
            dst_port: self.dst_ports,
            protocol: self.protocol,
            src_mac: self.src_mac,
            dst_mac: self.dst_mac,
            seq: 1,
            template_id,
            rng: rand::rng(),
            template: TemplateRecord::new(template_id, field_specifiers.into()),
            data_records_per_packet: 1,
            sync_stategy: strat,
        };
        (templates_map, gen)
    }
}

pub struct NetFlowGenerator<T> {
    src: NetAddr,
    dst: NetAddr,
    src_port: RangeInclusive<u16>,
    dst_port: RangeInclusive<u16>,
    protocol: Protocol,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    seq: u32,
    template_id: u16,
    rng: ThreadRng,
    sync_stategy: T,
    template: TemplateRecord,
    data_records_per_packet: u8,
}

impl<T> NetFlowGenerator<T> {
    fn data_records(&mut self) -> Vec<DataRecord> {
        (0..self.data_records_per_packet)
            .map(|_| {
                DataRecord::new(
                    vec![].into(),
                    vec![
                        ie::Field::sourceIPv4Address(self.src.get_one(&mut self.rng)),
                        ie::Field::destinationIPv4Address(self.dst.get_one(&mut self.rng)),
                        ie::Field::sourceTransportPort(
                            self.src_port.clone().choose(&mut self.rng).unwrap(),
                        ),
                        ie::Field::destinationTransportPort(
                            self.dst_port.clone().choose(&mut self.rng).unwrap(),
                        ),
                        ie::Field::sourceMacAddress(self.src_mac),
                        ie::Field::destinationMacAddress(self.dst_mac),
                        ie::Field::protocolIdentifier(self.protocol.into()),
                    ]
                    .into(),
                )
            })
            .collect()
    }
    fn template_packet(&self) -> NetFlowV9Packet {
        NetFlowV9Packet::new(
            System::uptime() as u32,
            Utc::now(),
            self.seq,
            0,
            vec![Set::Template(vec![self.template.clone()].into())].into(),
        )
    }
    fn data_packet(&mut self) -> NetFlowV9Packet {
        NetFlowV9Packet::new(
            System::uptime() as u32,
            Utc::now(),
            self.seq,
            0,
            vec![Set::Data {
                id: DataSetId::new(self.template_id).unwrap(),
                records: self.data_records().into(),
            }]
            .into(),
        )
    }
    fn mixed_packet(&mut self) -> NetFlowV9Packet {
        NetFlowV9Packet::new(
            System::uptime() as u32,
            Utc::now(),
            self.seq,
            0,
            vec![
                Set::Template(vec![self.template.clone()].into()),
                Set::Data {
                    id: DataSetId::new(self.template_id).unwrap(),
                    records: self.data_records().into(),
                },
            ]
            .into(),
        )
    }
}

impl Iterator for NetFlowGenerator<Once> {
    type Item = NetFlowV9Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let pkt = {
            if self.seq == 0 {
                self.template_packet()
            } else {
                self.data_packet()
            }
        };
        self.seq += 1;
        Some(pkt)
    }
}

impl Iterator for NetFlowGenerator<Every> {
    type Item = NetFlowV9Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let pkt = {
            if self.seq % self.sync_stategy.0 == 0 {
                self.template_packet()
            } else {
                self.data_packet()
            }
        };
        self.seq += 1;
        Some(pkt)
    }
}

impl Iterator for NetFlowGenerator<Interleve> {
    type Item = NetFlowV9Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let pkt = self.mixed_packet();
        self.seq += 1;
        Some(pkt)
    }
}
