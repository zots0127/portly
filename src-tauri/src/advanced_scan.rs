//! Portly 高级网络扫描模块 - 使用 pnet 进行底层扫描
//!
//! 需要 root/管理员权限才能使用完整功能
//! 如果没有权限，自动回退到基础扫描方法

use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::network::{discover_devices, NetworkDevice};

/// 高级扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedScanResult {
    pub devices: Vec<NetworkDevice>,
    pub scan_method: String,
    pub scan_time_ms: u64,
    pub has_permission: bool,
}

/// 检查是否有 root/管理员权限
pub fn check_raw_socket_permission() -> bool {
    // 尝试获取网络接口并创建原始套接字
    if let Some(interface) = get_default_interface() {
        match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(_, _)) => true,
            _ => false,
        }
    } else {
        false
    }
}

/// 获取默认网络接口
fn get_default_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    
    // 优先选择有 IP 地址且不是回环的接口
    interfaces.into_iter().find(|iface| {
        !iface.is_loopback() && 
        iface.is_up() && 
        !iface.ips.is_empty() &&
        iface.ips.iter().any(|ip| ip.is_ipv4())
    })
}

/// 高级 ARP 扫描（需要权限）
pub fn arp_scan_advanced(subnet: &str) -> Option<Vec<NetworkDevice>> {
    let interface = get_default_interface()?;
    
    // 尝试创建数据链路通道
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return None, // 没有权限
    };
    
    // 获取本机 MAC 和 IP
    let source_mac = interface.mac?;
    let source_ip = interface.ips.iter()
        .find_map(|ip| match ip {
            pnet::ipnetwork::IpNetwork::V4(net) => Some(net.ip()),
            _ => None,
        })?;
    
    // 解析目标子网
    let base_ip = subnet.split('/').next()?;
    let parts: Vec<&str> = base_ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    
    let mut devices = Vec::new();
    let start = Instant::now();
    
    // 发送 ARP 请求到子网内所有 IP
    for i in 1..=254 {
        let target_ip = Ipv4Addr::new(
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].parse().ok()?,
            i,
        );
        
        // 构造 ARP 请求包
        send_arp_request(&mut tx, source_mac, source_ip, target_ip);
    }
    
    // 接收 ARP 响应（最多等待 3 秒）
    let timeout = Duration::from_secs(3);
    while start.elapsed() < timeout {
        if let Ok(packet) = rx.next() {
            if let Some(ethernet) = EthernetPacket::new(packet) {
                if ethernet.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                        if arp.get_operation() == ArpOperations::Reply {
                            let ip = arp.get_sender_proto_addr().to_string();
                            let mac = arp.get_sender_hw_addr().to_string();
                            
                            // 避免重复
                            if !devices.iter().any(|d: &NetworkDevice| d.ip == ip) {
                                devices.push(NetworkDevice {
                                    ip,
                                    mac: Some(mac),
                                    hostname: None,
                                    is_online: true,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    
    // 按 IP 排序
    devices.sort_by(|a, b| {
        let a_num: u32 = a.ip.split('.').last().unwrap_or("0").parse().unwrap_or(0);
        let b_num: u32 = b.ip.split('.').last().unwrap_or("0").parse().unwrap_or(0);
        a_num.cmp(&b_num)
    });
    
    Some(devices)
}

/// 发送单个 ARP 请求
fn send_arp_request(
    tx: &mut Box<dyn datalink::DataLinkSender>,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) {
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);
    
    ethernet_packet.set_payload(arp_packet.packet());
    
    let _ = tx.send_to(ethernet_packet.packet(), None);
}

/// 智能扫描：优先使用高级扫描，失败时回退到基础扫描
pub fn smart_scan(subnet: &str) -> AdvancedScanResult {
    let start = Instant::now();
    
    // 尝试高级 ARP 扫描
    if let Some(devices) = arp_scan_advanced(subnet) {
        return AdvancedScanResult {
            devices,
            scan_method: "ARP (高级)".to_string(),
            scan_time_ms: start.elapsed().as_millis() as u64,
            has_permission: true,
        };
    }
    
    // 回退到基础扫描
    let devices = discover_devices(subnet);
    
    AdvancedScanResult {
        devices,
        scan_method: "Ping/ARP (基础)".to_string(),
        scan_time_ms: start.elapsed().as_millis() as u64,
        has_permission: false,
    }
}
