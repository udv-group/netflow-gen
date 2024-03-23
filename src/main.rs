use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU32;
use std::rc::Rc;

use anyhow::Context;
use chrono::Utc;
use clap::Parser;
use governor::{Quota, RateLimiter};
use netgauze_flow_pkt::netflow::TemplatesMap;
use netgauze_flow_pkt::{
    ie,
    netflow::{DataRecord, NetFlowV9Packet, Set, TemplateRecord},
    DataSetId, FieldSpecifier,
};
use netgauze_parse_utils::WritablePduWithTwoInputs;
use sysinfo::System;
use tokio::net::UdpSocket;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Adress of the Collector
    #[arg(short, long)]
    address: Ipv4Addr,

    /// Port of the Collector
    #[arg(short, long, default_value_t = 9995)]
    port: u16,

    /// Messages per second
    #[arg(short, long)]
    rate: NonZeroU32,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let addr = SocketAddrV4::new(args.address, args.port);
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("binding to udp socket")?;

    let templates_map: TemplatesMap = Rc::new(RefCell::new(HashMap::new()));
    let templ_id = 307;
    let source_id = 0;
    let field_specifiers = vec![
        FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
        FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
        FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
        FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
    ];
    let scope_filed_specifiers = vec![];

    templates_map.borrow_mut().insert(
        templ_id,
        Rc::new((scope_filed_specifiers, field_specifiers.clone())),
    );

    let template_packet = NetFlowV9Packet::new(
        System::uptime() as u32,
        Utc::now(),
        1,
        source_id,
        vec![Set::Template(vec![TemplateRecord::new(
            templ_id,
            field_specifiers,
        )])],
    );

    let mut buf = Vec::with_capacity(template_packet.len(None, true));
    let mut cursor = Cursor::new(&mut buf);
    template_packet.write(&mut cursor, None, true).unwrap();

    sock.send_to(&buf, addr).await?;
    println!("Send template");

    let mut data_buf = Vec::with_capacity(2048);
    let limiter = RateLimiter::direct(Quota::per_second(args.rate));

    println!("Sending Netflow Data packets");
    for seq in 1_u32.. {
        limiter.until_ready().await;
        let data_packet = NetFlowV9Packet::new(
            System::uptime() as u32,
            Utc::now(),
            seq,
            source_id,
            vec![Set::Data {
                id: DataSetId::new(templ_id).unwrap(),
                records: vec![DataRecord::new(
                    vec![],
                    vec![
                        ie::Field::sourceIPv4Address(ie::sourceIPv4Address(Ipv4Addr::new(
                            70, 1, 115, 1,
                        ))),
                        ie::Field::destinationIPv4Address(ie::destinationIPv4Address(
                            Ipv4Addr::new(50, 0, 71, 1),
                        )),
                        ie::Field::octetDeltaCount(ie::octetDeltaCount(1312)),
                        ie::Field::packetDeltaCount(ie::packetDeltaCount(9)),
                    ],
                )],
            }],
        );
        let len = data_packet.len(Some(Rc::clone(&templates_map)), true);
        let mut cursor = Cursor::new(&mut data_buf);
        data_packet
            .write(&mut cursor, Some(Rc::clone(&templates_map)), true)
            .unwrap();
        sock.send_to(&data_buf[..len], addr).await.unwrap();
    }
    Ok(())
}
