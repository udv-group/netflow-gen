use std::io::Cursor;
use std::net::SocketAddrV4;

use anyhow::Context;
use clap::Parser;
use governor::{Quota, RateLimiter};
use netgauze_flow_pkt::netflow::NetFlowV9Packet;
use netgauze_flow_pkt::netflow::TemplatesMap;
use netgauze_parse_utils::WritablePduWithTwoInputs;
use tokio::net::UdpSocket;

mod cli;
mod gen;

use crate::cli::Cli;
use crate::gen::NetFlowGenBuilder;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Cli::parse();
    let addr = SocketAddrV4::new(args.address, args.port);
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("binding to udp socket")?;

    let template_id = 307;
    let limiter = RateLimiter::direct(Quota::per_second(args.rate));

    let builder = NetFlowGenBuilder::default()
        .with_src_ip(args.src.ip.into())
        .with_dst_ip(args.dst.ip.into())
        .with_src_ports(args.src.ports.into())
        .with_dst_ports(args.dst.ports.into())
        .with_src_mac(args.src.mac)
        .with_dst_mac(args.dst.mac)
        .with_protocol(args.protocol);
    if args.templates.interleve {
        let (map, generator) = builder.send_template_with_data(template_id);
        println!("Sending Netflow packets with templates and data flows");
        for data_packet in generator {
            limiter.until_ready().await;
            send(data_packet, &map, &sock, addr).await;
        }
    } else if args.templates.once {
        let (map, mut generator) = builder.send_template_once(template_id);
        println!("Sending Netflow template packet");
        send(generator.next().unwrap(), &map, &sock, addr).await;
        println!("Sending Netflow data packets");
        for data_packet in generator {
            limiter.until_ready().await;
            send(data_packet, &map, &sock, addr).await;
        }
    } else {
        let (map, generator) =
            builder.send_template_every(template_id, args.templates.every.unwrap());
        println!(
            "Sending Netflow data packets with Netflow templates packet every {} packets",
            args.templates.every.unwrap()
        );
        for data_packet in generator {
            limiter.until_ready().await;
            send(data_packet, &map, &sock, addr).await;
        }
    }
    Ok(())
}

async fn send(pkt: NetFlowV9Packet, map: &TemplatesMap, sock: &UdpSocket, addr: SocketAddrV4) {
    let len = pkt.len(Some(map.clone()), true);
    let mut data_buf = Vec::with_capacity(len);
    let mut cursor = Cursor::new(&mut data_buf);
    pkt.write(&mut cursor, Some(map.clone()), true).unwrap();
    sock.send_to(&data_buf, addr).await.unwrap();
}
