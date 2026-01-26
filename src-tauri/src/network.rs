//! Portly 网络扫描模块 - 局域网设备发现和端口扫描
//!
//! 支持 macOS, Linux, Windows

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process::Command;
use std::time::Duration;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time::timeout;

/// 网络接口信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: String,
    pub netmask: String,
    pub subnet: String,
}

/// 局域网设备信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDevice {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub is_online: bool,
}

/// 远程端口扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemotePort {
    pub port: u16,
    pub is_open: bool,
    pub service: Option<String>,
}

/// 网络扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScanResult {
    pub subnet: String,
    pub devices: Vec<NetworkDevice>,
    pub scan_time: String,
}

/// 端口扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub ip: String,
    pub ports: Vec<RemotePort>,
    pub scan_time: String,
}

/// 常用端口及其服务名称
const COMMON_PORTS: &[(u16, &str)] = &[
    // 系统服务
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (139, "NetBIOS"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (465, "SMTPS"),
    (587, "SMTP-Submit"),
    (993, "IMAPS"),
    (995, "POP3S"),
    // 数据库
    (1433, "MSSQL"),
    (1521, "Oracle"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (5984, "CouchDB"),
    (6379, "Redis"),
    (9042, "Cassandra"),
    (9200, "Elasticsearch"),
    (27017, "MongoDB"),
    (28015, "RethinkDB"),
    // 消息队列
    (1883, "MQTT"),
    (4369, "Erlang-EPMD"),
    (5672, "RabbitMQ"),
    (6650, "Pulsar"),
    (9092, "Kafka"),
    (61616, "ActiveMQ"),
    // 缓存
    (11211, "Memcached"),
    // 远程访问
    (3389, "RDP"),
    (5900, "VNC"),
    (5901, "VNC-1"),
    // Web 服务
    (3000, "Node/Dev"),
    (4200, "Angular"),
    (5000, "Flask/ASP"),
    (5173, "Vite"),
    (8000, "Django/Py"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (8888, "Jupyter"),
    (9000, "PHP-FPM"),
    (9090, "Prometheus"),
    // 容器/编排
    (2375, "Docker"),
    (2376, "Docker-TLS"),
    (2379, "etcd"),
    (6443, "K8s-API"),
    (10250, "Kubelet"),
    // 开发工具
    (1420, "Tauri-Dev"),
    (3001, "Dev-Server"),
    (4000, "GraphQL"),
    (5555, "Android-ADB"),
    (8081, "React-Native"),
    (9229, "Node-Debug"),
    (19000, "Expo"),
    // 其他
    (111, "RPC"),
    (161, "SNMP"),
    (389, "LDAP"),
    (636, "LDAPS"),
    (873, "rsync"),
    (1194, "OpenVPN"),
    (1723, "PPTP"),
    (5353, "mDNS"),
    (8883, "MQTT-TLS"),
];

/// 获取本机网络接口列表
pub fn get_local_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    
    // 获取所有网络接口的 IP
    if let Ok(all_ips) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in all_ips {
            if let IpAddr::V4(ipv4) = ip {
                // 跳过回环地址
                if ipv4.is_loopback() {
                    continue;
                }
                
                let ip_str = ipv4.to_string();
                let octets = ipv4.octets();
                let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                
                // 避免重复
                if interfaces.iter().any(|i: &NetworkInterface| i.subnet == subnet) {
                    continue;
                }
                
                interfaces.push(NetworkInterface {
                    name: name.clone(),
                    ip: ip_str,
                    netmask: "255.255.255.0".to_string(),
                    subnet,
                });
            }
        }
    }
    
    // 如果没有找到，使用默认方法
    if interfaces.is_empty() {
        if let Ok(local_ip) = local_ip_address::local_ip() {
            if let IpAddr::V4(ipv4) = local_ip {
                let ip_str = ipv4.to_string();
                let octets = ipv4.octets();
                let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                
                interfaces.push(NetworkInterface {
                    name: "default".to_string(),
                    ip: ip_str,
                    netmask: "255.255.255.0".to_string(),
                    subnet,
                });
            }
        }
    }
    
    // 添加常用内网网段（作为备选）
    let common_subnets = [
        ("192.168.1.0/24", "192.168.1.x"),
        ("192.168.0.0/24", "192.168.0.x"),
        ("10.0.0.0/24", "10.0.0.x"),
    ];
    
    for (subnet, name) in common_subnets {
        if !interfaces.iter().any(|i| i.subnet == subnet) {
            interfaces.push(NetworkInterface {
                name: name.to_string(),
                ip: String::new(),
                netmask: "255.255.255.0".to_string(),
                subnet: subnet.to_string(),
            });
        }
    }
    
    // 把真实接口排在前面
    interfaces.sort_by(|a, b| {
        let a_has_ip = !a.ip.is_empty();
        let b_has_ip = !b.ip.is_empty();
        b_has_ip.cmp(&a_has_ip)
    });
    
    interfaces
}

/// 获取当前子网（自动检测）
pub fn get_current_subnet() -> Option<String> {
    if let Ok(local_ip) = local_ip_address::local_ip() {
        if let IpAddr::V4(ipv4) = local_ip {
            let octets = ipv4.octets();
            return Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]));
        }
    }
    None
}

/// 扫描局域网设备
pub fn discover_devices(subnet: &str) -> Vec<NetworkDevice> {
    // 解析子网
    let base_ip = subnet.split('/').next().unwrap_or("192.168.1.0");
    let parts: Vec<&str> = base_ip.split('.').collect();
    if parts.len() != 4 {
        return Vec::new();
    }
    
    let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
    
    // 先发送 ARP 请求刷新缓存
    #[cfg(target_os = "macos")]
    {
        // 在 macOS 上用 ping 刷新 ARP 缓存
        let _ = std::process::Command::new("ping")
            .args(["-c", "1", "-W", "100", &format!("{}.1", prefix)])
            .output();
    }
    
    // 使用 ARP 表获取已知设备（过滤 incomplete）
    let arp_devices = get_arp_table();
    
    // 使用 ping 扫描发现新设备（只返回成功响应的）
    let ping_results = ping_sweep(&prefix);
    
    // 合并结果
    let mut device_map: HashMap<String, NetworkDevice> = HashMap::new();
    
    // 添加 ARP 表中有效的设备（有 MAC 地址的）
    for device in arp_devices {
        if device.ip.starts_with(&prefix) {
            // 只添加有有效 MAC 地址的设备
            if let Some(ref mac) = device.mac {
                if !mac.contains("incomplete") && mac.len() >= 11 {
                    device_map.insert(device.ip.clone(), device);
                }
            }
        }
    }
    
    // 添加 ping 成功响应的设备
    for ip in &ping_results {
        if !device_map.contains_key(ip) {
            device_map.insert(ip.clone(), NetworkDevice {
                ip: ip.clone(),
                mac: None,
                hostname: None,
                is_online: true,
            });
        } else if let Some(d) = device_map.get_mut(ip) {
            d.is_online = true;
        }
    }
    
    // 标记未响应 ping 的设备为离线
    for device in device_map.values_mut() {
        if !ping_results.iter().any(|ip| ip == &device.ip) {
            device.is_online = false;
        }
    }
    
    // 只保留在线设备
    let mut devices: Vec<NetworkDevice> = device_map.into_values()
        .filter(|d| d.is_online)
        .collect();
    
    // 解析主机名
    for device in &mut devices {
        if device.hostname.is_none() {
            device.hostname = resolve_hostname(&device.ip);
        }
    }
    
    devices.sort_by(|a, b| {
        let a_num: u32 = a.ip.split('.').last().unwrap_or("0").parse().unwrap_or(0);
        let b_num: u32 = b.ip.split('.').last().unwrap_or("0").parse().unwrap_or(0);
        a_num.cmp(&b_num)
    });
    
    devices
}

/// 获取 ARP 表
fn get_arp_table() -> Vec<NetworkDevice> {
    let mut devices = Vec::new();
    
    #[cfg(target_os = "windows")]
    let output = Command::new("arp").args(["-a"]).output();
    
    #[cfg(not(target_os = "windows"))]
    let output = Command::new("arp").args(["-a"]).output();
    
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        
        for line in stdout.lines() {
            if let Some(device) = parse_arp_line(line) {
                devices.push(device);
            }
        }
    }
    
    devices
}

/// 解析 ARP 行
fn parse_arp_line(line: &str) -> Option<NetworkDevice> {
    // macOS/Linux 格式: hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff
    // Windows 格式: 192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic
    
    let parts: Vec<&str> = line.split_whitespace().collect();
    
    #[cfg(target_os = "windows")]
    {
        if parts.len() >= 2 {
            let ip = parts[0];
            if ip.contains('.') && !ip.starts_with("Interface") {
                let mac = if parts.len() > 1 { Some(parts[1].replace('-', ":")) } else { None };
                return Some(NetworkDevice {
                    ip: ip.to_string(),
                    mac,
                    hostname: None,
                    is_online: true,
                });
            }
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        // 查找 (IP) 格式
        for (i, part) in parts.iter().enumerate() {
            if part.starts_with('(') && part.ends_with(')') {
                let ip = part.trim_matches(|c| c == '(' || c == ')');
                if ip.contains('.') {
                    let mac = parts.get(i + 2).map(|s| s.to_string());
                    let hostname = if i > 0 && !parts[0].starts_with('?') {
                        Some(parts[0].to_string())
                    } else {
                        None
                    };
                    return Some(NetworkDevice {
                        ip: ip.to_string(),
                        mac,
                        hostname,
                        is_online: true,
                    });
                }
            }
        }
    }
    
    None
}

/// Ping 扫描
fn ping_sweep(prefix: &str) -> Vec<String> {
    let mut online_ips = Vec::new();
    
    // 使用多线程并发 ping
    let handles: Vec<_> = (1..=254)
        .map(|i| {
            let ip = format!("{}.{}", prefix, i);
            std::thread::spawn(move || {
                if ping_host(&ip) {
                    Some(ip)
                } else {
                    None
                }
            })
        })
        .collect();
    
    for handle in handles {
        if let Ok(Some(ip)) = handle.join() {
            online_ips.push(ip);
        }
    }
    
    online_ips
}

/// Ping 单个主机
fn ping_host(ip: &str) -> bool {
    #[cfg(target_os = "windows")]
    let output = Command::new("ping")
        .args(["-n", "1", "-w", "500", ip])
        .output();
    
    #[cfg(target_os = "macos")]
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "500", ip])
        .output();
    
    #[cfg(target_os = "linux")]
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "1", ip])
        .output();
    
    if let Ok(out) = output {
        out.status.success()
    } else {
        false
    }
}

/// 解析主机名
fn resolve_hostname(ip: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    let output = Command::new("nslookup").arg(ip).output();
    
    #[cfg(not(target_os = "windows"))]
    let output = Command::new("host").arg(ip).output();
    
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        // 解析输出中的主机名
        for line in stdout.lines() {
            if line.contains("name =") || line.contains("domain name pointer") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(name) = parts.last() {
                    return Some(name.trim_end_matches('.').to_string());
                }
            }
        }
    }
    None
}

/// 解析目标结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResult {
    pub original: String,
    pub ip: String,
    pub is_domain: bool,
    pub hostname: Option<String>,
}

/// 解析域名或验证 IP 地址
/// 支持输入：IP 地址 (如 192.168.1.1) 或域名 (如 example.com)
pub fn resolve_target(target: &str) -> Result<ResolveResult, String> {
    let target = target.trim();
    
    // 首先检查是否已经是有效的 IP 地址
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ResolveResult {
            original: target.to_string(),
            ip: ip.to_string(),
            is_domain: false,
            hostname: resolve_hostname(&ip.to_string()),
        });
    }
    
    // 尝试解析域名
    use std::net::ToSocketAddrs;
    
    // 添加端口以便解析
    let addr_str = format!("{}:80", target);
    
    match addr_str.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                let ip = addr.ip().to_string();
                Ok(ResolveResult {
                    original: target.to_string(),
                    ip,
                    is_domain: true,
                    hostname: Some(target.to_string()),
                })
            } else {
                Err(format!("无法解析: {}", target))
            }
        }
        Err(e) => Err(format!("DNS 解析失败: {} ({})", target, e)),
    }
}


/// 扫描远程主机端口（同步版本，用于快速扫描）
pub fn scan_ports_sync(ip: &str, ports: &[u16], timeout_ms: u64) -> Vec<RemotePort> {
    let timeout_duration = Duration::from_millis(timeout_ms);
    let mut results = Vec::new();
    
    for &port in ports {
        let addr = format!("{}:{}", ip, port);
        let is_open = if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
            TcpStream::connect_timeout(&socket_addr, timeout_duration).is_ok()
        } else {
            false
        };
        
        let service = if is_open {
            get_service_name(port)
        } else {
            None
        };
        
        results.push(RemotePort {
            port,
            is_open,
            service,
        });
    }
    
    results
}

/// 异步扫描端口（更快）
pub async fn scan_ports_async(ip: &str, ports: &[u16], timeout_ms: u64) -> Vec<RemotePort> {
    let timeout_duration = Duration::from_millis(timeout_ms);
    let mut handles = Vec::new();
    
    for &port in ports {
        let ip_clone = ip.to_string();
        let handle = tokio::spawn(async move {
            let addr = format!("{}:{}", ip_clone, port);
            let is_open = if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
                timeout(timeout_duration, TokioTcpStream::connect(socket_addr))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
            } else {
                false
            };
            
            let service = if is_open {
                get_service_name(port)
            } else {
                None
            };
            
            RemotePort { port, is_open, service }
        });
        handles.push(handle);
    }
    
    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }
    
    results.sort_by_key(|r| r.port);
    results
}

/// 获取端口对应的服务名称
fn get_service_name(port: u16) -> Option<String> {
    COMMON_PORTS
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, name)| name.to_string())
}

/// 获取常用端口列表
pub fn get_common_ports() -> Vec<u16> {
    COMMON_PORTS.iter().map(|(p, _)| *p).collect()
}

/// 生成端口范围
pub fn port_range(start: u16, end: u16) -> Vec<u16> {
    (start..=end).collect()
}

/// 快速扫描（只扫描常用端口）
pub fn quick_scan(ip: &str) -> Vec<RemotePort> {
    let ports = get_common_ports();
    scan_ports_sync(ip, &ports, 500)
}

/// 完整扫描（扫描指定范围）
pub fn full_scan(ip: &str, start: u16, end: u16, timeout_ms: u64) -> Vec<RemotePort> {
    let ports = port_range(start, end);
    scan_ports_sync(ip, &ports, timeout_ms)
}

// ===== Ping 和 Traceroute 功能 =====

/// Ping 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub ip: String,
    pub is_reachable: bool,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub packet_loss: f32,
    pub min_ms: Option<f32>,
    pub avg_ms: Option<f32>,
    pub max_ms: Option<f32>,
    pub raw_output: String,
}

/// 单次 Ping 结果（用于流式显示）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingOneResult {
    pub ip: String,
    pub seq: u32,
    pub success: bool,
    pub time_ms: Option<f32>,
    pub ttl: Option<u32>,
    pub line: String,
}

/// Traceroute 跳数信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHop {
    pub hop: u32,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub time_ms: Option<f32>,
}

/// Traceroute 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteResult {
    pub target: String,
    pub hops: Vec<TraceHop>,
    pub raw_output: String,
}

/// 执行 Ping 测试
pub fn ping_test(ip: &str, count: u32) -> PingResult {
    #[cfg(target_os = "windows")]
    let output = Command::new("ping")
        .args(["-n", &count.to_string(), ip])
        .output();
    
    #[cfg(target_os = "macos")]
    let output = Command::new("ping")
        .args(["-c", &count.to_string(), ip])
        .output();
    
    #[cfg(target_os = "linux")]
    let output = Command::new("ping")
        .args(["-c", &count.to_string(), ip])
        .output();
    
    let mut result = PingResult {
        ip: ip.to_string(),
        is_reachable: false,
        packets_sent: count,
        packets_received: 0,
        packet_loss: 100.0,
        min_ms: None,
        avg_ms: None,
        max_ms: None,
        raw_output: String::new(),
    };
    
    if let Ok(out) = output {
        result.raw_output = String::from_utf8_lossy(&out.stdout).to_string();
        result.is_reachable = out.status.success();
        
        // 解析输出 - 先克隆避免借用冲突
        let output_clone = result.raw_output.clone();
        parse_ping_output(&output_clone, &mut result);
    }
    
    result
}

/// 执行单次 Ping（用于流式显示）
pub fn ping_one(ip: &str, seq: u32) -> PingOneResult {
    #[cfg(target_os = "windows")]
    let output = Command::new("ping")
        .args(["-n", "1", "-w", "2000", ip])
        .output();
    
    #[cfg(target_os = "macos")]
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "2000", ip])  // macOS -W 是毫秒
        .output();
    
    #[cfg(target_os = "linux")]
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "2", ip])  // Linux -W 是秒
        .output();
    
    let mut result = PingOneResult {
        ip: ip.to_string(),
        seq,
        success: false,
        time_ms: None,
        ttl: None,
        line: String::new(),
    };
    
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        
        // 解析输出行 - 只有真正收到响应才算成功
        for line in stdout.lines() {
            if line.contains("bytes from") || line.contains("Reply from") {
                result.line = line.to_string();
                result.success = true; // 只有找到响应行才设为成功
                
                // 提取 time
                if let Some(pos) = line.find("time=") {
                    let after = &line[pos + 5..];
                    let time_str: String = after.chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.')
                        .collect();
                    result.time_ms = time_str.parse().ok();
                }
                // macOS 可能用 "time " 格式
                else if let Some(pos) = line.find("time ") {
                    let after = &line[pos + 5..];
                    let time_str: String = after.chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.')
                        .collect();
                    result.time_ms = time_str.parse().ok();
                }
                
                // 提取 ttl
                if let Some(pos) = line.to_lowercase().find("ttl=") {
                    let after = &line[pos + 4..];
                    let ttl_str: String = after.chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    result.ttl = ttl_str.parse().ok();
                }
                
                break;
            }
        }
        
        // 没有收到响应
        if result.line.is_empty() {
            result.line = "Request timeout".to_string();
            result.success = false;
        }
    }
    
    result
}

/// 解析 Ping 输出
fn parse_ping_output(output: &str, result: &mut PingResult) {
    for line in output.lines() {
        let line_lower = line.to_lowercase();
        
        // 解析丢包率
        if line_lower.contains("packet loss") || line_lower.contains("packets") {
            // macOS/Linux: "4 packets transmitted, 4 received, 0% packet loss"
            // Windows: "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
            if let Some(loss) = extract_packet_loss(line) {
                result.packet_loss = loss;
                result.packets_received = ((100.0 - loss) / 100.0 * result.packets_sent as f32) as u32;
            }
        }
        
        // 解析延迟统计
        if line_lower.contains("min/avg/max") || line_lower.contains("minimum") {
            // macOS/Linux: "round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.5 ms"
            if let Some((min, avg, max)) = extract_latency_stats(line) {
                result.min_ms = Some(min);
                result.avg_ms = Some(avg);
                result.max_ms = Some(max);
            }
        }
    }
}

/// 提取丢包率
fn extract_packet_loss(line: &str) -> Option<f32> {
    // 查找百分比数字
    let re_patterns = ["%", "% packet loss", "% loss"];
    for pattern in re_patterns {
        if let Some(pos) = line.find(pattern) {
            let before = &line[..pos];
            let num_str: String = before.chars().rev()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect::<String>()
                .chars().rev().collect();
            if let Ok(loss) = num_str.parse::<f32>() {
                return Some(loss);
            }
        }
    }
    None
}

/// 提取延迟统计
fn extract_latency_stats(line: &str) -> Option<(f32, f32, f32)> {
    // 查找 "= X/Y/Z" 格式
    if let Some(pos) = line.find('=') {
        let stats_part = &line[pos + 1..];
        let parts: Vec<&str> = stats_part.split('/').collect();
        if parts.len() >= 3 {
            let min = parts[0].trim().parse::<f32>().ok()?;
            let avg = parts[1].trim().parse::<f32>().ok()?;
            let max = parts[2].trim().split_whitespace().next()?.parse::<f32>().ok()?;
            return Some((min, avg, max));
        }
    }
    None
}

/// 执行 Traceroute
pub fn traceroute(ip: &str) -> TracerouteResult {
    #[cfg(target_os = "windows")]
    let output = Command::new("tracert")
        .args(["-d", "-w", "1000", ip])
        .output();
    
    #[cfg(target_os = "macos")]
    let output = Command::new("traceroute")
        .args(["-n", "-w", "2", "-q", "1", ip])
        .output();
    
    #[cfg(target_os = "linux")]
    let output = Command::new("traceroute")
        .args(["-n", "-w", "2", "-q", "1", ip])
        .output();
    
    let mut result = TracerouteResult {
        target: ip.to_string(),
        hops: Vec::new(),
        raw_output: String::new(),
    };
    
    if let Ok(out) = output {
        result.raw_output = String::from_utf8_lossy(&out.stdout).to_string();
        
        // 解析输出
        for line in result.raw_output.lines() {
            if let Some(hop) = parse_traceroute_line(line) {
                result.hops.push(hop);
            }
        }
    }
    
    result
}

/// 解析 Traceroute 行
fn parse_traceroute_line(line: &str) -> Option<TraceHop> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    
    // 第一部分应该是跳数
    let hop_num = parts[0].parse::<u32>().ok()?;
    
    // 查找 IP 地址和延迟
    let mut ip = None;
    let mut time_ms = None;
    
    for part in &parts[1..] {
        // 检查是否是 IP 地址
        if part.contains('.') && part.chars().all(|c| c.is_ascii_digit() || c == '.') {
            ip = Some(part.to_string());
        }
        // 检查是否是延迟时间 (e.g., "1.234" 后跟 "ms")
        else if let Ok(ms) = part.parse::<f32>() {
            time_ms = Some(ms);
        }
    }
    
    // 超时的情况
    if line.contains('*') && ip.is_none() {
        return Some(TraceHop {
            hop: hop_num,
            ip: None,
            hostname: None,
            time_ms: None,
        });
    }
    
    if ip.is_some() || time_ms.is_some() {
        Some(TraceHop {
            hop: hop_num,
            ip,
            hostname: None,
            time_ms,
        })
    } else {
        None
    }
}

// ===== 服务类型探测 =====

/// 服务类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub service: String,
    pub service_type: String,  // "api", "web", "database", "other"
    pub server: Option<String>,
    pub content_type: Option<String>,
}

/// 探测 HTTP 服务类型
pub fn detect_service_type(ip: &str, port: u16) -> ServiceInfo {
    let base_service = get_service_name(port).unwrap_or_else(|| "Unknown".to_string());
    
    // 对于 HTTP 端口，尝试探测
    if is_http_port(port) {
        if let Some(info) = probe_http_service(ip, port) {
            return info;
        }
    }
    
    // 根据端口推断类型
    let service_type = infer_service_type(port);
    
    ServiceInfo {
        port,
        service: base_service,
        service_type,
        server: None,
        content_type: None,
    }
}

/// 判断是否是 HTTP 端口
fn is_http_port(port: u16) -> bool {
    matches!(port, 
        80 | 443 | 3000 | 3001 | 4000 | 4200 | 5000 | 5173 | 
        8000 | 8080 | 8081 | 8443 | 8888 | 9000 | 9090 | 19000
    )
}

/// 探测 HTTP 服务
fn probe_http_service(ip: &str, port: u16) -> Option<ServiceInfo> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    
    let addr = format!("{}:{}", ip, port);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_secs(2)
    ).ok()?;
    
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok()?;
    
    // 发送简单的 HTTP 请求
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Portly/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        ip
    );
    stream.write_all(request.as_bytes()).ok()?;
    
    // 读取响应
    let mut buffer = vec![0u8; 4096];
    let n = stream.read(&mut buffer).ok()?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    
    // 解析响应头
    let mut server = None;
    let mut content_type = None;
    let mut service_type = "web".to_string();
    
    for line in response.lines() {
        let line_lower = line.to_lowercase();
        
        if line_lower.starts_with("server:") {
            server = Some(line[7..].trim().to_string());
        }
        if line_lower.starts_with("content-type:") {
            let ct = line[13..].trim().to_string();
            content_type = Some(ct.clone());
            
            // 根据 Content-Type 判断类型
            if ct.contains("application/json") || ct.contains("api") {
                service_type = "api".to_string();
            } else if ct.contains("text/html") {
                service_type = "web".to_string();
            } else if ct.contains("application/xml") || ct.contains("text/xml") {
                service_type = "api".to_string();
            }
        }
        
        // 检查特殊标识
        if line_lower.contains("x-powered-by:") {
            let powered = line.to_lowercase();
            if powered.contains("express") || powered.contains("flask") || 
               powered.contains("django") || powered.contains("fastapi") {
                service_type = "api".to_string();
            }
        }
    }
    
    // 检查响应体中的特征
    let body = response.to_lowercase();
    if body.contains("<!doctype html") || body.contains("<html") {
        if body.contains("react") || body.contains("vue") || body.contains("angular") ||
           body.contains("next") || body.contains("vite") {
            service_type = "web".to_string();
        }
    } else if body.starts_with("{") || body.contains("\"data\":") || body.contains("\"error\":") {
        service_type = "api".to_string();
    }
    
    let service = match service_type.as_str() {
        "api" => format!("API ({})", port),
        "web" => format!("Web ({})", port),
        _ => get_service_name(port).unwrap_or_else(|| format!("HTTP ({})", port)),
    };
    
    Some(ServiceInfo {
        port,
        service,
        service_type,
        server,
        content_type,
    })
}

/// 根据端口推断服务类型
fn infer_service_type(port: u16) -> String {
    match port {
        // 数据库
        1433 | 1521 | 3306 | 5432 | 5984 | 6379 | 9042 | 9200 | 27017 | 28015 => "database",
        // 消息队列
        1883 | 5672 | 6650 | 9092 | 61616 => "queue",
        // 缓存
        11211 => "cache",
        // Web 服务
        80 | 443 | 3000 | 4200 | 5173 | 8080 | 8443 => "web",
        // API 服务
        4000 | 5000 | 8000 | 9000 => "api",
        // 其他
        _ => "other",
    }.to_string()
}

/// 批量探测服务类型
pub fn detect_services(ip: &str, ports: &[u16]) -> Vec<ServiceInfo> {
    ports.iter()
        .filter_map(|&port| {
            // 先检查端口是否开放
            let addr = format!("{}:{}", ip, port);
            if TcpStream::connect_timeout(
                &addr.parse().ok()?,
                Duration::from_millis(500)
            ).is_ok() {
                Some(detect_service_type(ip, port))
            } else {
                None
            }
        })
        .collect()
}

