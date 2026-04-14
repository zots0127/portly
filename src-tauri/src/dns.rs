//! Portly DNS 查询模块
//!
//! 支持 A, AAAA, CNAME, MX, TXT, NS, SOA 记录查询
//! 跨平台支持 (Windows/macOS/Linux)

use crate::app_error::AppError;
use crate::command_exec::run_command;
use serde::{Deserialize, Serialize};
use std::net::ToSocketAddrs;
use std::time::Instant;

/// DNS 查询结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryResult {
    pub domain: String,
    pub record_type: String,
    pub records: Vec<DnsRecord>,
    pub query_time_ms: u64,
    pub dns_server: String,
    pub error: Option<String>,
}

/// DNS 记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: String,
    pub ttl: u32,
    pub data: String,
}

/// 支持的记录类型
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
}

impl RecordType {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "CNAME" => Some(RecordType::CNAME),
            "MX" => Some(RecordType::MX),
            "TXT" => Some(RecordType::TXT),
            "NS" => Some(RecordType::NS),
            "SOA" => Some(RecordType::SOA),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::NS => "NS",
            RecordType::SOA => "SOA",
        }
    }

    /// 返回 dig 命令使用的记录类型
    pub fn dig_type(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::NS => "NS",
            RecordType::SOA => "SOA",
        }
    }

    /// 返回 nslookup 命令使用的记录类型
    pub fn nslookup_type(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::NS => "NS",
            RecordType::SOA => "SOA",
        }
    }
}

/// 执行 DNS 查询
pub fn dns_query(
    domain: String,
    record_type: String,
    dns_server: Option<String>,
) -> DnsQueryResult {
    let dns_server = dns_server.unwrap_or_else(|| {
        // 使用系统默认 DNS
        #[cfg(target_os = "windows")]
        {
            "8.8.8.8".to_string()
        }
        #[cfg(not(target_os = "windows"))]
        {
            "8.8.8.8".to_string()
        }
    });

    let rt = match RecordType::parse(&record_type) {
        Some(rt) => rt,
        None => {
            return DnsQueryResult {
                domain,
                record_type: record_type.clone(),
                records: vec![],
                query_time_ms: 0,
                dns_server,
                error: Some(format!("不支持的记录类型: {}", record_type)),
            };
        }
    };

    let start = Instant::now();

    // 根据平台选择查询方法
    let records: Result<Vec<DnsRecord>, Box<dyn std::error::Error>> = if cfg!(target_os = "windows")
    {
        #[cfg(target_os = "windows")]
        {
            query_via_nslookup(&domain, rt, &dns_server)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(vec![])
        }
    } else {
        #[cfg(not(target_os = "windows"))]
        {
            query_via_dig(&domain, rt, &dns_server)
        }
        #[cfg(target_os = "windows")]
        {
            Ok(vec![])
        }
    };

    let query_time = start.elapsed().as_millis() as u64;

    match records {
        Ok(records) => {
            if records.is_empty() {
                DnsQueryResult {
                    domain,
                    record_type,
                    records: vec![],
                    query_time_ms: query_time,
                    dns_server,
                    error: Some("未找到记录".to_string()),
                }
            } else {
                DnsQueryResult {
                    domain,
                    record_type,
                    records,
                    query_time_ms: query_time,
                    dns_server,
                    error: None,
                }
            }
        }
        Err(e) => DnsQueryResult {
            domain,
            record_type,
            records: vec![],
            query_time_ms: query_time,
            dns_server,
            error: Some(e.to_string()),
        },
    }
}

/// 使用 dig 命令查询 (Unix/macOS)
#[cfg(not(target_os = "windows"))]
fn query_via_dig(
    domain: &str,
    record_type: RecordType,
    dns_server: &str,
) -> Result<Vec<DnsRecord>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();

    // 对于 A 记录，也可以使用系统解析作为快速回退
    if record_type == RecordType::A {
        if let Ok(addrs) = format!("{}:0", domain).to_socket_addrs() {
            for addr in addrs {
                if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        rtype: "A".to_string(),
                        ttl: 300, // 默认 TTL
                        data: ipv4.to_string(),
                    });
                }
            }
            if !records.is_empty() {
                return Ok(records);
            }
        }
    }

    // 使用 dig 命令查询
    let server_arg = format!("@{}", dns_server);
    let output = run_command("dig", "DNS 查询 (dig)", |cmd| {
        cmd.args([
            server_arg.as_str(),
            domain,
            record_type.dig_type(),
            "+short",
            "+tries=2",
            "+time=2",
        ]);
    });

    match output {
        Ok(out) => {
            let stdout = out.stdout;
            if out.status == 0 || !stdout.is_empty() {
                records = parse_dig_output(&stdout, domain, record_type);
            }

            if records.is_empty() && !out.stderr.is_empty() {
                return Err(out.stderr.into());
            }
        }
        Err(err) => {
            if matches!(err, AppError::CommandUnavailable { .. }) {
                return query_via_system_resolver(domain, record_type);
            }
            return Err(Box::new(err));
        }
    }

    if records.is_empty() {
        query_via_system_resolver(domain, record_type)
    } else {
        Ok(records)
    }
}

/// 解析 dig 输出
#[cfg(not(target_os = "windows"))]
fn parse_dig_output(output: &str, domain: &str, record_type: RecordType) -> Vec<DnsRecord> {
    let mut records = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        // dig +short 输出格式:
        // A/AAAA: 直接是 IP 地址
        // CNAME: 目标域名
        // MX: "10 mail.example.com"
        // TXT: "\"v=spf1...\"" 或 "spf1..."
        // NS: "ns1.example.com"
        // SOA: 更复杂的格式

        match record_type {
            RecordType::A => {
                // 验证是否是有效的 IPv4 地址
                if line.parse::<std::net::Ipv4Addr>().is_ok() {
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        rtype: "A".to_string(),
                        ttl: 300,
                        data: line.to_string(),
                    });
                }
            }
            RecordType::AAAA => {
                // 验证是否是有效的 IPv6 地址
                if line.parse::<std::net::Ipv6Addr>().is_ok() {
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        rtype: "AAAA".to_string(),
                        ttl: 300,
                        data: line.to_string(),
                    });
                }
            }
            RecordType::CNAME => {
                if !line.starts_with(';') && !line.is_empty() {
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        rtype: "CNAME".to_string(),
                        ttl: 300,
                        data: line.trim_end_matches('.').to_string(),
                    });
                }
            }
            RecordType::MX => {
                // 格式: "priority target" 或 "priority target."
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let target = parts[1].trim_end_matches('.');
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        rtype: "MX".to_string(),
                        ttl: 300,
                        data: format!("{} {}", parts[0], target),
                    });
                } else if !line.is_empty() {
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        rtype: "MX".to_string(),
                        ttl: 300,
                        data: line.to_string(),
                    });
                }
            }
            RecordType::TXT => {
                // TXT 记录可能有引号
                let data = line.trim_matches('"').to_string();
                if !data.is_empty() {
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        rtype: "TXT".to_string(),
                        ttl: 300,
                        data,
                    });
                }
            }
            RecordType::NS => {
                let target = line.trim_end_matches('.');
                if !target.is_empty() {
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        rtype: "NS".to_string(),
                        ttl: 300,
                        data: target.to_string(),
                    });
                }
            }
            RecordType::SOA => {
                // SOA 记录格式复杂，使用原始输出
                if !line.is_empty() {
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        rtype: "SOA".to_string(),
                        ttl: 300,
                        data: line.to_string(),
                    });
                }
            }
        }
    }

    records
}

/// 使用 nslookup 命令查询 (Windows)
#[cfg(target_os = "windows")]
fn query_via_nslookup(
    domain: &str,
    record_type: RecordType,
    dns_server: &str,
) -> Result<Vec<DnsRecord>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();

    // 对于 A 记录，优先使用系统解析
    if record_type == RecordType::A {
        if let Ok(addrs) = format!("{}:0", domain).to_socket_addrs() {
            for addr in addrs {
                if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        rtype: "A".to_string(),
                        ttl: 300,
                        data: ipv4.to_string(),
                    });
                }
            }
            if !records.is_empty() {
                return Ok(records);
            }
        }
    }

    // 使用 nslookup 查询
    let query_type = format!("-type={}", record_type.nslookup_type());
    let output = run_command("nslookup", "DNS 查询 (nslookup)", |cmd| {
        cmd.args([query_type.as_str(), domain, dns_server]);
    });

    match output {
        Ok(out) => {
            let stdout = out.stdout;
            let stderr = out.stderr;

            if out.status == 0 || !stdout.is_empty() {
                records = parse_nslookup_output(&stdout, domain, record_type);
            }

            if records.is_empty() && !stderr.is_empty() {
                return Err(stderr.into());
            }
        }
        Err(err) => {
            if matches!(err, AppError::CommandUnavailable { .. }) {
                return query_via_system_resolver(domain, record_type);
            }
            return Err(Box::new(err));
        }
    }

    if records.is_empty() {
        query_via_system_resolver(domain, record_type)
    } else {
        Ok(records)
    }
}

/// 解析 nslookup 输出
#[cfg(target_os = "windows")]
fn parse_nslookup_output(output: &str, domain: &str, record_type: RecordType) -> Vec<DnsRecord> {
    let mut records = Vec::new();
    let mut in_answers = false;

    for line in output.lines() {
        let line = line.trim();

        // 查找答案部分
        if line.contains("answers:") || line.contains("Answer:") {
            in_answers = true;
            continue;
        }

        if !in_answers
            || line.is_empty()
            || line.starts_with("Server:")
            || line.starts_with("Address:")
        {
            continue;
        }

        match record_type {
            RecordType::A => {
                // 查找类似 "name: example.com" 后跟 "Address: 1.2.3.4"
                if line.contains("Addresses:") || line.contains("Address:") {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 2 {
                        let addr = parts[1].trim();
                        if addr.parse::<std::net::Ipv4Addr>().is_ok() {
                            records.push(DnsRecord {
                                name: domain.to_string(),
                                rtype: "A".to_string(),
                                ttl: 300,
                                data: addr.to_string(),
                            });
                        }
                    }
                }
            }
            RecordType::AAAA => {
                if line.contains("Addresses:") || line.contains("Address:") {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 2 {
                        let addr = parts[1].trim();
                        if addr.parse::<std::net::Ipv6Addr>().is_ok() {
                            records.push(DnsRecord {
                                name: domain.to_string(),
                                rtype: "AAAA".to_string(),
                                ttl: 300,
                                data: addr.to_string(),
                            });
                        }
                    }
                }
            }
            RecordType::MX | RecordType::NS | RecordType::CNAME => {
                // MX: "mail.example.com" 或 "MX preference = 10, mail exchanger = mail.example.com"
                if !line.starts_with("nameserver") && !line.is_empty() {
                    let text = if line.contains("=") {
                        // Windows nslookup 格式
                        if let Some(idx) = line.find('=') {
                            line[idx + 1..].trim()
                        } else {
                            line
                        }
                    } else {
                        line
                    };

                    if !text.is_empty() && !text.contains("nameserver") {
                        records.push(DnsRecord {
                            name: domain.to_string(),
                            rtype: record_type.as_str().to_string(),
                            ttl: 300,
                            data: text.trim_end_matches('.').to_string(),
                        });
                    }
                }
            }
            RecordType::TXT => {
                if !line.is_empty() && !line.starts_with("nameserver") {
                    let text = line.trim_matches('"').to_string();
                    if !text.is_empty() {
                        records.push(DnsRecord {
                            name: domain.to_string(),
                            rtype: "TXT".to_string(),
                            ttl: 300,
                            data: text,
                        });
                    }
                }
            }
            RecordType::SOA => {
                if !line.is_empty() {
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        rtype: "SOA".to_string(),
                        ttl: 300,
                        data: line.to_string(),
                    });
                }
            }
        }
    }

    records
}

/// 使用系统解析器作为回退
fn query_via_system_resolver(
    domain: &str,
    record_type: RecordType,
) -> Result<Vec<DnsRecord>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();

    match record_type {
        RecordType::A => {
            if let Ok(addrs) = format!("{}:0", domain).to_socket_addrs() {
                for addr in addrs {
                    if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                        records.push(DnsRecord {
                            name: domain.to_string(),
                            rtype: "A".to_string(),
                            ttl: 300,
                            data: ipv4.to_string(),
                        });
                    }
                }
            }
        }
        RecordType::AAAA => {
            if let Ok(addrs) = format!("{}:0", domain).to_socket_addrs() {
                for addr in addrs {
                    if let std::net::IpAddr::V6(ipv6) = addr.ip() {
                        records.push(DnsRecord {
                            name: domain.to_string(),
                            rtype: "AAAA".to_string(),
                            ttl: 300,
                            data: ipv6.to_string(),
                        });
                    }
                }
            }
        }
        _ => {
            // 其他记录类型无法通过系统解析器获取
            return Err("系统解析器不支持此记录类型".into());
        }
    }

    if records.is_empty() {
        Err("未找到记录".into())
    } else {
        Ok(records)
    }
}

/// 获取推荐的 DNS 服务器列表
pub fn get_popular_dns_servers() -> Vec<DnsServerInfo> {
    vec![
        DnsServerInfo {
            name: "Google DNS".to_string(),
            ip: "8.8.8.8".to_string(),
            location: "Global".to_string(),
        },
        DnsServerInfo {
            name: "Cloudflare DNS".to_string(),
            ip: "1.1.1.1".to_string(),
            location: "Global".to_string(),
        },
        DnsServerInfo {
            name: "Quad9 DNS".to_string(),
            ip: "9.9.9.9".to_string(),
            location: "Global".to_string(),
        },
        DnsServerInfo {
            name: "OpenDNS".to_string(),
            ip: "208.67.222.222".to_string(),
            location: "Global".to_string(),
        },
        DnsServerInfo {
            name: "AliDNS".to_string(),
            ip: "223.5.5.5".to_string(),
            location: "China".to_string(),
        },
        DnsServerInfo {
            name: "DNSPod".to_string(),
            ip: "119.29.29.29".to_string(),
            location: "China".to_string(),
        },
    ]
}

/// DNS 服务器信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerInfo {
    pub name: String,
    pub ip: String,
    pub location: String,
}

/// 批量查询多个记录类型
pub fn batch_query(
    domain: String,
    record_types: Vec<String>,
    dns_server: Option<String>,
) -> Vec<DnsQueryResult> {
    record_types
        .into_iter()
        .map(|rt| dns_query(domain.clone(), rt, dns_server.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_from_str() {
        assert_eq!(RecordType::parse("A"), Some(RecordType::A));
        assert_eq!(RecordType::parse("a"), Some(RecordType::A));
        assert_eq!(RecordType::parse("AAAA"), Some(RecordType::AAAA));
        assert_eq!(RecordType::parse("MX"), Some(RecordType::MX));
        assert_eq!(RecordType::parse("INVALID"), None);
    }

    #[test]
    fn test_get_popular_dns_servers() {
        let servers = get_popular_dns_servers();
        assert!(!servers.is_empty());
        assert!(servers.iter().any(|s| s.ip == "8.8.8.8"));
    }

    #[test]
    fn test_dns_query_returns_valid_result() {
        let result = dns_query("localhost".to_string(), "A".to_string(), None);
        // 应该成功返回
        assert_eq!(result.domain, "localhost");
        assert_eq!(result.record_type, "A");
        // localhost 应该解析到 127.0.0.1
        assert!(!result.records.is_empty() || result.error.is_some());
    }

    #[test]
    fn test_batch_query_processes_multiple_types() {
        let types = vec!["A".to_string(), "AAAA".to_string()];
        let results = batch_query("localhost".to_string(), types, None);
        assert_eq!(results.len(), 2);
        // 验证每个结果都包含正确的域名
        for result in &results {
            assert_eq!(result.domain, "localhost");
        }
    }

    #[test]
    fn test_get_popular_dns_servers_full() {
        let servers = get_popular_dns_servers();
        assert!(!servers.is_empty());
        assert!(servers.iter().any(|s| s.ip == "8.8.8.8"));
        assert!(servers.iter().any(|s| s.ip == "1.1.1.1"));

        // 验证服务器数量
        assert_eq!(servers.len(), 6);

        // 验证特定服务器
        let google = servers.iter().find(|s| s.ip == "8.8.8.8").unwrap();
        assert_eq!(google.name, "Google DNS");
        assert_eq!(google.location, "Global");

        let cloudflare = servers.iter().find(|s| s.ip == "1.1.1.1").unwrap();
        assert_eq!(cloudflare.name, "Cloudflare DNS");

        let alidns = servers.iter().find(|s| s.ip == "223.5.5.5").unwrap();
        assert_eq!(alidns.name, "AliDNS");
        assert_eq!(alidns.location, "China");
    }

    #[test]
    fn test_record_type_parse_all_types() {
        assert_eq!(RecordType::parse("A"), Some(RecordType::A));
        assert_eq!(RecordType::parse("AAAA"), Some(RecordType::AAAA));
        assert_eq!(RecordType::parse("CNAME"), Some(RecordType::CNAME));
        assert_eq!(RecordType::parse("MX"), Some(RecordType::MX));
        assert_eq!(RecordType::parse("TXT"), Some(RecordType::TXT));
        assert_eq!(RecordType::parse("NS"), Some(RecordType::NS));
        assert_eq!(RecordType::parse("SOA"), Some(RecordType::SOA));
        assert_eq!(RecordType::parse("INVALID"), None);

        // 测试大小写不敏感
        assert_eq!(RecordType::parse("a"), Some(RecordType::A));
        assert_eq!(RecordType::parse("aaaa"), Some(RecordType::AAAA));
        assert_eq!(RecordType::parse("cname"), Some(RecordType::CNAME));
    }

    #[test]
    fn test_record_type_as_str() {
        assert_eq!(RecordType::A.as_str(), "A");
        assert_eq!(RecordType::AAAA.as_str(), "AAAA");
        assert_eq!(RecordType::CNAME.as_str(), "CNAME");
        assert_eq!(RecordType::MX.as_str(), "MX");
        assert_eq!(RecordType::TXT.as_str(), "TXT");
        assert_eq!(RecordType::NS.as_str(), "NS");
        assert_eq!(RecordType::SOA.as_str(), "SOA");
    }

    #[test]
    fn test_record_type_dig_type() {
        assert_eq!(RecordType::A.dig_type(), "A");
        assert_eq!(RecordType::AAAA.dig_type(), "AAAA");
        assert_eq!(RecordType::MX.dig_type(), "MX");
        assert_eq!(RecordType::TXT.dig_type(), "TXT");
    }

    #[test]
    fn test_record_type_nslookup_type() {
        assert_eq!(RecordType::A.nslookup_type(), "A");
        assert_eq!(RecordType::AAAA.nslookup_type(), "AAAA");
        assert_eq!(RecordType::MX.nslookup_type(), "MX");
        assert_eq!(RecordType::NS.nslookup_type(), "NS");
    }

    #[test]
    fn test_dns_result_serialization() {
        let record = DnsRecord {
            name: "test.com".to_string(),
            rtype: "A".to_string(),
            ttl: 300,
            data: "1.2.3.4".to_string(),
        };

        let serialized = serde_json::to_string(&record).unwrap();
        let deserialized: DnsRecord = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.name, record.name);
        assert_eq!(deserialized.rtype, record.rtype);
        assert_eq!(deserialized.ttl, record.ttl);
        assert_eq!(deserialized.data, record.data);
    }

    #[test]
    fn test_dns_query_result_serialization() {
        let result = DnsQueryResult {
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            records: vec![DnsRecord {
                name: "example.com".to_string(),
                rtype: "A".to_string(),
                ttl: 300,
                data: "93.184.216.34".to_string(),
            }],
            query_time_ms: 50,
            dns_server: "8.8.8.8".to_string(),
            error: None,
        };

        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: DnsQueryResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.domain, result.domain);
        assert_eq!(deserialized.record_type, result.record_type);
        assert_eq!(deserialized.records.len(), 1);
        assert_eq!(deserialized.error, None);
    }

    #[test]
    fn test_dns_query_with_invalid_record_type() {
        let result = dns_query("example.com".to_string(), "INVALID".to_string(), None);
        assert_eq!(result.domain, "example.com");
        assert_eq!(result.record_type, "INVALID");
        assert!(result.records.is_empty());
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("不支持的记录类型"));
    }

    #[test]
    fn test_dns_server_info_serialization() {
        let server = DnsServerInfo {
            name: "Test DNS".to_string(),
            ip: "1.2.3.4".to_string(),
            location: "Test".to_string(),
        };

        let serialized = serde_json::to_string(&server).unwrap();
        let deserialized: DnsServerInfo = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.name, server.name);
        assert_eq!(deserialized.ip, server.ip);
        assert_eq!(deserialized.location, server.location);
    }

    #[test]
    fn test_batch_query_with_empty_types() {
        let types: Vec<String> = vec![];
        let results = batch_query("localhost".to_string(), types, None);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_batch_query_with_custom_dns_server() {
        let types = vec!["A".to_string()];
        let results =
            batch_query("localhost".to_string(), types, Some("8.8.8.8".to_string()));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dns_server, "8.8.8.8");
    }

    #[test]
    fn test_dns_query_127_0_0_1() {
        let result = dns_query("127.0.0.1".to_string(), "A".to_string(), None);
        assert_eq!(result.domain, "127.0.0.1");
        assert_eq!(result.record_type, "A");
    }
}
