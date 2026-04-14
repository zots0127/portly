//! Whois 查询模块

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResult {
    pub domain: String,
    pub registrar: Option<String>,
    pub created: Option<String>,
    pub expires: Option<String>,
    pub updated: Option<String>,
    pub status: Vec<String>,
    pub nameservers: Vec<String>,
    pub dnssec: Option<String>,
    pub raw_output: String,
    pub error: Option<String>,
}

/// 常用 Whois 服务器
const DEFAULT_WHOIS_SERVER: &str = "whois.iana.org";
const WHOIS_PORT: u16 = 43;

/// 执行 Whois 查询
pub fn whois_query(domain: String) -> WhoisResult {
    let normalized_domain = domain.to_lowercase().trim().to_string();

    // 首先查询 IANA 获取正确的 whois 服务器
    let whois_server = find_whois_server(&normalized_domain);

    let raw_output = match query_whois_server(&normalized_domain, &whois_server) {
        Ok(output) => output,
        Err(e) => {
            return WhoisResult {
                domain,
                registrar: None,
                created: None,
                expires: None,
                updated: None,
                status: vec![],
                nameservers: vec![],
                dnssec: None,
                raw_output: String::new(),
                error: Some(e.to_string()),
            };
        }
    };

    // 解析 whois 输出
    parse_whois_output(&domain, &raw_output)
}

fn find_whois_server(domain: &str) -> String {
    // 对于常见 TLD，直接返回对应的 whois 服务器
    let tld = domain.split('.').next_back().unwrap_or("");

    match tld {
        "com" => "whois.verisign.com",
        "net" => "whois.verisign.com",
        "org" => "whois.pir.org",
        "io" => "whois.nic.io",
        "co" => "whois.nic.co",
        "ai" => "whois.nic.ai",
        "dev" => "whois.nic.google",
        "app" => "whois.nic.google",
        "cn" => "whois.cnnic.cn",
        "jp" => "whois.jprs.jp",
        "uk" => "whois.nic.uk",
        "de" => "whois.denic.de",
        "fr" => "whois.nic.fr",
        "ru" => "whois.tld.ru",
        "biz" => "whois.nic.biz",
        "info" => "whois.nic.info",
        "me" => "whois.nic.me",
        "tv" => "whois.nic.tv",
        "xyz" => "whois.nic.xyz",
        "cc" => "whois.nic.cc",
        "ly" => "whois.nic.ly",
        "sh" => "whois.nic.sh",
        "tech" => "whois.nic.tech",
        "online" => "whois.nic.online",
        "site" => "whois.nic.site",
        "club" => "whois.nic.club",
        "fun" => "whois.nic.fun",
        "store" => "whois.nic.store",
        "shop" => "whois.nic.shop",
        "blog" => "whois.nic.blog",
        "gg" => "whois.nic.gg",
        "eu" => "whois.eu",
        "ca" => "whois.ca.fury.ca",
        "us" => "whois.nic.us",
        "in" => "whois.registry.in",
        "au" => "whois.auda.org.au",
        _ => DEFAULT_WHOIS_SERVER,
    }
    .to_string()
}

fn query_whois_server(domain: &str, server: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(format!("{}:{}", server, WHOIS_PORT))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    // 发送查询
    writeln!(stream, "{}", domain)?;

    // 读取响应
    let reader = BufReader::new(stream);
    let mut output = String::new();

    for line in reader.lines() {
        let line = line?;
        output.push_str(&line);
        output.push('\n');
    }

    Ok(output)
}

fn parse_whois_output(domain: &str, raw: &str) -> WhoisResult {
    let mut result = WhoisResult {
        domain: domain.to_string(),
        registrar: None,
        created: None,
        expires: None,
        updated: None,
        status: vec![],
        nameservers: vec![],
        dnssec: None,
        raw_output: raw.to_string(),
        error: None,
    };

    // 解析常见的 whois 字段
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
            continue;
        }

        let lower = line.to_lowercase();

        // 提取注册商
        if lower.contains("registrar") || lower.contains("sponsoring registrar") {
            if let Some(value) = extract_field_value(line) {
                if result.registrar.is_none() {
                    result.registrar = Some(value);
                }
            }
        }

        // 提取创建时间
        if lower.contains("creation date")
            || lower.contains("created:")
            || lower.contains("registered:")
            || lower.contains("registration time:")
            || lower.contains("domain date:")
        {
            if let Some(value) = extract_field_value(line) {
                if result.created.is_none() {
                    result.created = Some(value);
                }
            }
        }

        // 提取过期时间
        if lower.contains("expiration date")
            || lower.contains("expires:")
            || lower.contains("expiry date:")
            || lower.contains("registry expiry date:")
        {
            if let Some(value) = extract_field_value(line) {
                if result.expires.is_none() {
                    result.expires = Some(value);
                }
            }
        }

        // 提取更新时间
        if lower.contains("updated:")
            || lower.contains("last updated:")
            || lower.contains("modified:")
            || lower.contains("last update of:")
            || lower.contains("updated date:")
        {
            if let Some(value) = extract_field_value(line) {
                if result.updated.is_none() {
                    result.updated = Some(value);
                }
            }
        }

        // 提取状态
        if lower.contains("status:") || lower.contains("domain status:") {
            if let Some(value) = extract_field_value(line) {
                result.status.push(value);
            }
        }

        // 提取域名服务器
        if lower.contains("name server:")
            || lower.contains("nserver:")
            || lower.contains("nameserver:")
            || lower.contains("ns:")
        {
            if let Some(value) = extract_field_value(line) {
                result.nameservers.push(value.to_lowercase());
            }
        }

        // 提取 DNSSEC
        if lower.contains("dnssec:") {
            if let Some(value) = extract_field_value(line) {
                result.dnssec = Some(value);
            }
        }
    }

    // 去重 nameservers
    result.nameservers.sort();
    result.nameservers.dedup();
    result.status.sort();
    result.status.dedup();

    result
}

fn extract_field_value(line: &str) -> Option<String> {
    // 查找冒号后的值
    if let Some(colon_pos) = line.find(':') {
        let value = line[colon_pos + 1..].trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_whois_server_for_common_tlds() {
        // 测试常见 TLD 返回正确的服务器
        assert_eq!(find_whois_server("example.com"), "whois.verisign.com");
        assert_eq!(find_whois_server("example.net"), "whois.verisign.com");
        assert_eq!(find_whois_server("example.org"), "whois.pir.org");
        assert_eq!(find_whois_server("example.io"), "whois.nic.io");
        assert_eq!(find_whois_server("example.cn"), "whois.cnnic.cn");
        assert_eq!(find_whois_server("example.jp"), "whois.jprs.jp");
        assert_eq!(find_whois_server("example.uk"), "whois.nic.uk");
        assert_eq!(find_whois_server("example.de"), "whois.denic.de");
    }

    #[test]
    fn test_find_whois_server_unknown_tld() {
        // 测试未知 TLD 返回默认服务器
        assert_eq!(find_whois_server("example.unknown"), "whois.iana.org");
    }

    #[test]
    fn test_extract_field_value() {
        // 测试字段值提取
        assert_eq!(extract_field_value("key: value"), Some("value".to_string()));
        assert_eq!(extract_field_value("key:value"), Some("value".to_string()));
        assert_eq!(extract_field_value("key:"), None);
        assert_eq!(extract_field_value("no colon here"), None);
    }

    #[test]
    fn test_parse_whois_output_structure() {
        let output = "Registrar: Example Registrar
Created: 2020-01-01T00:00:00Z
Expires: 2025-01-01T00:00:00Z
Registry Expiry Date: 2025-01-01T00:00:00Z
Domain Status: clientTransferProhibited
Name Server: ns1.example.com
DNSSEC: unsigned

Domain: EXAMPLE.COM
";
        let result = parse_whois_output("example.com", output);
        assert_eq!(result.domain, "example.com");
        assert!(result.registrar.is_some());
        assert!(result.created.is_some());
        assert!(result.expires.is_some());
        assert!(!result.status.is_empty());
    }

    #[test]
    fn test_parse_whois_output_empty() {
        let result = parse_whois_output("example.com", "");
        assert_eq!(result.domain, "example.com");
        assert!(result.registrar.is_none());
        assert!(result.raw_output.is_empty());
    }

    #[test]
    fn test_whois_result_serialization() {
        let result = WhoisResult {
            domain: "test.com".to_string(),
            registrar: Some("Test Registrar".to_string()),
            created: Some("2020-01-01".to_string()),
            expires: None,
            updated: None,
            status: vec!["active".to_string()],
            nameservers: vec![],
            dnssec: None,
            raw_output: "test output".to_string(),
            error: None,
        };

        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: WhoisResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.domain, result.domain);
        assert_eq!(deserialized.registrar, result.registrar);
    }

    #[test]
    fn test_find_whois_server_additional_tlds() {
        // 测试其他支持的 TLD
        assert_eq!(find_whois_server("example.co"), "whois.nic.co");
        assert_eq!(find_whois_server("example.ai"), "whois.nic.ai");
        assert_eq!(find_whois_server("example.dev"), "whois.nic.google");
        assert_eq!(find_whois_server("example.app"), "whois.nic.google");
        assert_eq!(find_whois_server("example.fr"), "whois.nic.fr");
        assert_eq!(find_whois_server("example.ru"), "whois.tld.ru");
        assert_eq!(find_whois_server("example.biz"), "whois.nic.biz");
        assert_eq!(find_whois_server("example.info"), "whois.nic.info");
        assert_eq!(find_whois_server("example.me"), "whois.nic.me");
        assert_eq!(find_whois_server("example.tv"), "whois.nic.tv");
        assert_eq!(find_whois_server("example.xyz"), "whois.nic.xyz");
        assert_eq!(find_whois_server("example.cc"), "whois.nic.cc");
        assert_eq!(find_whois_server("example.eu"), "whois.eu");
        assert_eq!(find_whois_server("example.ca"), "whois.ca.fury.ca");
        assert_eq!(find_whois_server("example.us"), "whois.nic.us");
        assert_eq!(find_whois_server("example.in"), "whois.registry.in");
        assert_eq!(find_whois_server("example.au"), "whois.auda.org.au");
    }

    #[test]
    fn test_extract_field_value_with_spaces() {
        // 测试带空格的字段值
        assert_eq!(
            extract_field_value("  key:  value with spaces  "),
            Some("value with spaces".to_string())
        );
        assert_eq!(extract_field_value("key:    "), None);
    }

    #[test]
    fn test_parse_whois_output_multiple_nameservers() {
        let output = "Name Server: ns1.example.com
Name Server: ns2.example.com
Name Server: ns3.example.com
Registrar: Test Registrar
";
        let result = parse_whois_output("example.com", output);
        assert_eq!(result.nameservers.len(), 3);
        assert!(result.nameservers.contains(&"ns1.example.com".to_string()));
        assert!(result.nameservers.contains(&"ns2.example.com".to_string()));
        assert!(result.nameservers.contains(&"ns3.example.com".to_string()));
    }

    #[test]
    fn test_parse_whois_output_nameserver_deduplication() {
        let output = "Name Server: ns1.example.com
Name Server: ns2.example.com
Name Server: ns1.example.com
nserver: ns2.example.com
";
        let result = parse_whois_output("example.com", output);
        // nameservers 应该被去重并排序
        assert_eq!(result.nameservers.len(), 2);
        assert_eq!(result.nameservers[0], "ns1.example.com");
        assert_eq!(result.nameservers[1], "ns2.example.com");
    }

    #[test]
    fn test_parse_whois_output_status_deduplication() {
        let output = "Domain Status: clientTransferProhibited
Domain Status: clientDeleteProhibited
Status: clientTransferProhibited
";
        let result = parse_whois_output("example.com", output);
        // status 应该被去重并排序
        assert_eq!(result.status.len(), 2);
    }

    #[test]
    fn test_parse_whois_output_comment_filtering() {
        let output = "# This is a comment
% This is another comment
Registrar: Test Registrar

Domain: EXAMPLE.COM
";
        let result = parse_whois_output("example.com", output);
        assert_eq!(result.registrar, Some("Test Registrar".to_string()));
    }

    #[test]
    fn test_whois_result_serialization_with_none_fields() {
        let result = WhoisResult {
            domain: "test.com".to_string(),
            registrar: None,
            created: None,
            expires: None,
            updated: None,
            status: vec![],
            nameservers: vec![],
            dnssec: None,
            raw_output: String::new(),
            error: None,
        };

        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: WhoisResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.domain, "test.com");
        assert!(deserialized.registrar.is_none());
        assert!(deserialized.created.is_none());
        assert!(deserialized.status.is_empty());
    }

    #[test]
    fn test_whois_result_serialization_with_error() {
        let result = WhoisResult {
            domain: "test.com".to_string(),
            registrar: None,
            created: None,
            expires: None,
            updated: None,
            status: vec![],
            nameservers: vec![],
            dnssec: None,
            raw_output: String::new(),
            error: Some("Network error".to_string()),
        };

        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: WhoisResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.error, Some("Network error".to_string()));
    }

    #[test]
    fn test_find_whois_server_subdomain() {
        // 测试子域名也能正确提取 TLD
        assert_eq!(find_whois_server("www.example.com"), "whois.verisign.com");
        assert_eq!(find_whois_server("mail.example.net"), "whois.verisign.com");
        assert_eq!(find_whois_server("blog.example.org"), "whois.pir.org");
        assert_eq!(find_whois_server("api.example.io"), "whois.nic.io");
    }

    #[test]
    fn test_parse_whois_output_alternative_date_formats() {
        let output = "Creation Date: 2020-01-01T00:00:00Z
registered: 2020-01-01
Registration Time: 1580155200
";
        let result = parse_whois_output("example.com", output);
        // 应该匹配到第一个创建日期
        assert!(result.created.is_some());
    }

    #[test]
    fn test_parse_whois_output_dnssec() {
        let output = "DNSSEC: signedDelegation
Registrar: Test Registrar
";
        let result = parse_whois_output("example.com", output);
        assert_eq!(result.dnssec, Some("signedDelegation".to_string()));
    }
}
