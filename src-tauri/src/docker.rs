//! Docker 容器端口集成模块

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::command_exec::run_command;

/// Docker 容器信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub ports: Vec<DockerPort>,
}

/// Docker 端口映射
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerPort {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
    pub host_ip: String,
}

/// 检查 Docker 是否可用
pub fn is_docker_available() -> bool {
    run_command("docker", "Docker 可用性检测", |cmd| {
        cmd.args(["version", "--format", "{{.Client.Version}}"]);
    })
    .map(|o| o.status == 0)
    .unwrap_or(false)
}

/// 获取所有运行中的 Docker 容器
pub fn get_docker_containers() -> Vec<DockerContainer> {
    let output = match run_command("docker", "Docker 容器列表读取", |cmd| {
        cmd.args([
            "ps",
            "--format",
            "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
        ]);
    }) {
        Ok(o) if o.status == 0 => o,
        _ => return Vec::new(),
    };

    let stdout = output.stdout;
    let mut containers = Vec::new();

    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 4 {
            let ports = if parts.len() >= 5 {
                parse_docker_ports(parts[4])
            } else {
                Vec::new()
            };

            containers.push(DockerContainer {
                id: parts[0].to_string(),
                name: parts[1].to_string(),
                image: parts[2].to_string(),
                status: parts[3].to_string(),
                ports,
            });
        }
    }

    containers
}

/// 解析 Docker 端口字符串
/// 格式: "0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp"
fn parse_docker_ports(port_str: &str) -> Vec<DockerPort> {
    let mut ports = Vec::new();

    for part in port_str.split(", ") {
        if let Some(port) = parse_single_port_mapping(part) {
            // 避免重复（IPv4 和 IPv6 可能重复）
            if !ports
                .iter()
                .any(|p: &DockerPort| p.host_port == port.host_port && p.protocol == port.protocol)
            {
                ports.push(port);
            }
        }
    }

    ports
}

/// 解析单个端口映射
/// 格式: "0.0.0.0:5432->5432/tcp" 或 "5432/tcp" (仅暴露不映射)
fn parse_single_port_mapping(s: &str) -> Option<DockerPort> {
    // 跳过 IPv6 格式
    if s.starts_with("[::]:") || s.contains(":::") {
        return None;
    }

    // 解析 host:port->container_port/protocol
    if let Some(arrow_pos) = s.find("->") {
        let host_part = &s[..arrow_pos];
        let container_part = &s[arrow_pos + 2..];

        // 解析 host_ip:host_port
        let (host_ip, host_port_str) = if let Some(colon_pos) = host_part.rfind(':') {
            (&host_part[..colon_pos], &host_part[colon_pos + 1..])
        } else {
            ("0.0.0.0", host_part)
        };

        // 解析端口范围
        let host_port: u16 = if host_port_str.contains('-') {
            // 端口范围，取第一个
            host_port_str.split('-').next()?.parse().ok()?
        } else {
            host_port_str.parse().ok()?
        };

        // 解析 container_port/protocol
        let (container_port_str, protocol) = if let Some(slash_pos) = container_part.find('/') {
            (
                &container_part[..slash_pos],
                &container_part[slash_pos + 1..],
            )
        } else {
            (container_part, "tcp")
        };

        let container_port: u16 = if container_port_str.contains('-') {
            container_port_str.split('-').next()?.parse().ok()?
        } else {
            container_port_str.parse().ok()?
        };

        return Some(DockerPort {
            host_port,
            container_port,
            protocol: protocol.to_string(),
            host_ip: host_ip.to_string(),
        });
    }

    None
}

/// 获取端口到容器的映射表
pub fn get_port_to_container_map() -> HashMap<u16, String> {
    let containers = get_docker_containers();
    let mut map = HashMap::new();

    for container in containers {
        for port in &container.ports {
            map.insert(port.host_port, format!("🐳 {}", container.name));
        }
    }

    map
}

/// 获取容器端口详细信息
pub fn get_docker_port_info(port: u16) -> Option<(String, String)> {
    let containers = get_docker_containers();

    for container in containers {
        for p in &container.ports {
            if p.host_port == port {
                return Some((container.name.clone(), container.image.clone()));
            }
        }
    }

    None
}

/// 从容器列表中获取端口信息（用于测试）
pub fn get_docker_port_info_from_containers(
    containers: &[DockerContainer],
    port: u16,
) -> Option<(String, DockerPort)> {
    for container in containers {
        for p in &container.ports {
            if p.host_port == port {
                return Some((
                    container.name.clone(),
                    DockerPort {
                        host_port: p.host_port,
                        container_port: p.container_port,
                        protocol: p.protocol.clone(),
                        host_ip: p.host_ip.clone(),
                    },
                ));
            }
        }
    }

    None
}

/// 解析 Docker ps 输出（用于测试）
pub fn parse_docker_ps_output(output: &str) -> Vec<DockerContainer> {
    let mut containers = Vec::new();

    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('\n').collect();
        if parts.len() >= 4 {
            let ports = if parts.len() >= 5 {
                parse_docker_ports(parts[4])
            } else {
                Vec::new()
            };

            containers.push(DockerContainer {
                id: parts[0].to_string(),
                name: parts[1].to_string(),
                image: parts[2].to_string(),
                status: parts[3].to_string(),
                ports,
            });
        }
    }

    containers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_port_serialization() {
        let port = DockerPort {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
            host_ip: "0.0.0.0".to_string(),
        };

        let serialized = serde_json::to_string(&port).unwrap();
        let deserialized: DockerPort = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.host_port, 8080);
        assert_eq!(deserialized.container_port, 80);
    }

    #[test]
    fn test_docker_container_full_serialization() {
        let container = DockerContainer {
            id: "abc123".to_string(),
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            status: "running".to_string(),
            ports: vec![],
        };

        let serialized = serde_json::to_string(&container).unwrap();
        let deserialized: DockerContainer = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.name, "test-container");
        assert_eq!(deserialized.image, "nginx:latest");
    }

    #[test]
    fn test_parse_docker_ports_empty() {
        let ports = parse_docker_ports("");
        assert!(ports.is_empty());
    }

    #[test]
    fn test_parse_docker_ports_single_mapping() {
        let ports = parse_docker_ports("0.0.0.0:8080->80/tcp");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].host_port, 8080);
        assert_eq!(ports[0].container_port, 80);
        assert_eq!(ports[0].protocol, "tcp");
        assert_eq!(ports[0].host_ip, "0.0.0.0");
    }

    #[test]
    fn test_parse_docker_ports_multiple_mappings() {
        let ports = parse_docker_ports("0.0.0.0:8080->80/tcp, 0.0.0.0:8443->443/tcp");
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].host_port, 8080);
        assert_eq!(ports[1].host_port, 8443);
    }

    #[test]
    fn test_parse_docker_ports_ipv6_filtered() {
        let ports = parse_docker_ports("[::]:8080->80/tcp");
        // IPv6 格式应该被过滤掉
        assert_eq!(ports.len(), 0);
    }

    #[test]
    fn test_parse_docker_ports_default_host_ip() {
        let ports = parse_docker_ports("8080->80/tcp");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].host_ip, "0.0.0.0");
    }

    #[test]
    fn test_parse_docker_ports_udp_protocol() {
        let ports = parse_docker_ports("0.0.0.0:53->53/udp");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].protocol, "udp");
    }

    #[test]
    fn test_parse_docker_ports_no_protocol() {
        let ports = parse_docker_ports("8080->80");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].protocol, "tcp");
    }

    #[test]
    fn test_get_docker_port_info_from_containers_found() {
        let containers = vec![DockerContainer {
            id: "test".to_string(),
            name: "nginx".to_string(),
            image: "nginx:latest".to_string(),
            status: "running".to_string(),
            ports: vec![DockerPort {
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".to_string(),
                host_ip: "0.0.0.0".to_string(),
            }],
        }];

        let result = get_docker_port_info_from_containers(&containers, 8080);
        assert!(result.is_some());
        let (name, port) = result.unwrap();
        assert_eq!(name, "nginx");
        assert_eq!(port.host_port, 8080);
    }

    #[test]
    fn test_get_docker_port_info_from_containers_not_found() {
        let containers = vec![];
        let result = get_docker_port_info_from_containers(&containers, 9999);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_docker_port_info_from_containers_multiple_containers() {
        let containers = vec![
            DockerContainer {
                id: "1".to_string(),
                name: "nginx".to_string(),
                image: "nginx:latest".to_string(),
                status: "running".to_string(),
                ports: vec![DockerPort {
                    host_port: 80,
                    container_port: 80,
                    protocol: "tcp".to_string(),
                    host_ip: "0.0.0.0".to_string(),
                }],
            },
            DockerContainer {
                id: "2".to_string(),
                name: "postgres".to_string(),
                image: "postgres:15".to_string(),
                status: "running".to_string(),
                ports: vec![DockerPort {
                    host_port: 5432,
                    container_port: 5432,
                    protocol: "tcp".to_string(),
                    host_ip: "0.0.0.0".to_string(),
                }],
            },
        ];

        let result = get_docker_port_info_from_containers(&containers, 5432);
        assert!(result.is_some());
        let (name, port) = result.unwrap();
        assert_eq!(name, "postgres");
        assert_eq!(port.container_port, 5432);
    }

    #[test]
    fn test_docker_port_with_range() {
        let ports = parse_docker_ports("0.0.0.0:8000-8005->80/tcp");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].host_port, 8000);
        assert_eq!(ports[0].container_port, 80);
    }

    #[test]
    fn test_parse_docker_ports_duplicate_filtered() {
        // IPv4 和 IPv6 可能产生相同的端口映射，应该去重
        let ports = parse_docker_ports("0.0.0.0:8080->80/tcp, 0.0.0.0:8080->80/tcp");
        assert_eq!(ports.len(), 1);
    }

    #[test]
    fn test_docker_container_with_multiple_ports() {
        let container = DockerContainer {
            id: "abc123".to_string(),
            name: "multi-port".to_string(),
            image: "test:latest".to_string(),
            status: "running".to_string(),
            ports: vec![
                DockerPort {
                    host_port: 80,
                    container_port: 80,
                    protocol: "tcp".to_string(),
                    host_ip: "0.0.0.0".to_string(),
                },
                DockerPort {
                    host_port: 443,
                    container_port: 443,
                    protocol: "tcp".to_string(),
                    host_ip: "0.0.0.0".to_string(),
                },
            ],
        };

        assert_eq!(container.ports.len(), 2);
        assert_eq!(container.ports[0].host_port, 80);
        assert_eq!(container.ports[1].host_port, 443);
    }
}
