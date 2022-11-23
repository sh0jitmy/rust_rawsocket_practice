extern crate pnet;
extern crate pnet_datalink;

use pnet_datalink::{NetworkInterface};
use pnet_datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use std::env;

fn capture_packet(packet: &EthernetPacket) {
  //　イーサネットの上位のプロトコルを確認
  match packet.get_ethertype() {
    // Ipv4上のtcpまたはudpを表示
    EtherTypes::Ipv4 => {
      let ipv4 = Ipv4Packet::new(packet.payload());
      if let Some(ipv4) = ipv4 {
        match ipv4.get_next_level_protocol() {
          IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(ipv4.payload());
            if let Some(tcp) = tcp {
              println!("TCP {}:{} -> {}:{}", ipv4.get_source(), tcp.get_source(), ipv4.get_destination(), tcp.get_destination());
            }
          }
          IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(ipv4.payload());
            if let Some(udp) = udp {
              println!("UDP {}:{} -> {}:{}", ipv4.get_source(), udp.get_source(), ipv4.get_destination(), udp.get_destination());
            }
          }
          _ => println!("not tcp"),
        }
      }
    }
    _ => println!("not ipv4"),
  }
}

fn main() {
  // インターフェース名を引き数で取得
  let network_interface = env::args().nth(1).unwrap();

  // すべてのネットワークインターフェースを取得
  let interfaces = pnet_datalink::interfaces();

  // インターフェースを取得
  let interface = interfaces.into_iter().filter(|interface: &NetworkInterface| interface.name == network_interface).next().expect("Failed get Inteface");
  println!("Inteface:{}",interface.name);

  // 送受信に使うソケット的なものを取得
  let (mut tx, mut rx) = match pnet_datalink::channel(&interface, Default::default()) {
    Ok(Ethernet(tx, rx)) => (tx, rx),
    Ok(_) => panic!("not ethernet"),
    Err(e) => {
      panic!("error ocrrued {}", e);
    }
  };

  println!("Sniffing...");
  // ループの中でパケットを受信する
  loop {
    match rx.next() {
      Ok(packet) => {
        let packet = EthernetPacket::new(packet).unwrap();
        capture_packet(&packet);
      }
      Err(e) => {
        panic!("error occured {}",e);
      }
    }
  }
}

