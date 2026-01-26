//! Docker 容器端口集成模块

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::collections::HashMap;

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
    Command::new("docker")
        .args(["version", "--format", "{{.Client.Version}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 获取所有运行中的 Docker 容器
pub fn get_docker_containers() -> Vec<DockerContainer> {
    let output = match Command::new("docker")
        .args(["ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
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
            if !ports.iter().any(|p: &DockerPort| p.host_port == port.host_port && p.protocol == port.protocol) {
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
            (&container_part[..slash_pos], &container_part[slash_pos + 1..])
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
