//! Portly 核心库 - 跨平台端口扫描器
//!
//! 支持 macOS, Linux, Windows

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

// Windows CREATE_NO_WINDOW flag to hide console windows
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// 端口信息结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub address: String,
    pub pid: String,
    pub process: String,
    pub user: String,
    pub command: Option<String>,
}

/// 扫描结果
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_time: String,
    pub total_ports: usize,
    pub unique_apps: usize,
    pub ports: Vec<PortInfo>,
}

/// 按应用分组的结果
#[derive(Debug, Serialize, Deserialize)]
pub struct AppGroup {
    pub process: String,
    pub pid: String,
    pub ports: Vec<u16>,
    pub command: Option<String>,
}

/// 跨平台获取监听端口
pub fn get_listening_ports_raw() -> Vec<PortInfo> {
    #[cfg(target_os = "macos")]
    {
        get_ports_macos()
    }
    
    #[cfg(target_os = "linux")]
    {
        get_ports_linux()
    }
    
    #[cfg(target_os = "windows")]
    {
        get_ports_windows()
    }
}

/// macOS: 使用 lsof
#[cfg(target_os = "macos")]
fn get_ports_macos() -> Vec<PortInfo> {
    let output = match Command::new("lsof")
        .args(["-i", "-P", "-n"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let mut ports = parse_lsof_output(&String::from_utf8_lossy(&output.stdout));
    
    // 获取完整进程名称（lsof 会截断进程名）
    let mut name_cache: HashMap<String, String> = HashMap::new();
    for port in &mut ports {
        let full_name = name_cache
            .entry(port.pid.clone())
            .or_insert_with(|| get_full_process_name(&port.pid).unwrap_or_else(|| port.process.clone()))
            .clone();
        port.process = full_name;
    }
    
    ports
}

/// 获取进程的完整名称
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn get_full_process_name(pid: &str) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", pid, "-o", "comm="])
        .output()
        .ok()?;
    
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if name.is_empty() { 
        None 
    } else { 
        Some(name) 
    }
}

/// Linux: 使用 ss 或 lsof
#[cfg(target_os = "linux")]
fn get_ports_linux() -> Vec<PortInfo> {
    let output = Command::new("ss").args(["-tlnp"]).output();
    
    if let Ok(o) = output {
        if o.status.success() {
            return parse_ss_output(&String::from_utf8_lossy(&o.stdout));
        }
    }
    
    let output = match Command::new("lsof").args(["-i", "-P", "-n"]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    parse_lsof_output(&String::from_utf8_lossy(&output.stdout))
}

/// Windows: 使用 netstat
#[cfg(target_os = "windows")]
fn get_ports_windows() -> Vec<PortInfo> {
    let output = match Command::new("netstat")
        .args(["-ano"])
        .creation_flags(CREATE_NO_WINDOW)
        .output() 
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    parse_netstat_windows(&String::from_utf8_lossy(&output.stdout))
}

/// 解析 lsof 输出
fn parse_lsof_output(stdout: &str) -> Vec<PortInfo> {
    let mut ports = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in stdout.lines().skip(1) {
        if !line.contains("LISTEN") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }

        let process_name = parts[0].to_string();
        let pid = parts[1].to_string();
        let user = parts[2].to_string();
        let addr_port = parts[8];

        let port: u16 = match addr_port.rsplit(':').next().and_then(|p| p.parse().ok()) {
            Some(n) => n,
            None => continue,
        };

        let address = if addr_port.starts_with("*:") {
            "*".to_string()
        } else if let Some(pos) = addr_port.rfind(':') {
            addr_port[..pos].to_string()
        } else {
            "*".to_string()
        };

        let fd_type = if parts.len() > 4 { parts[4] } else { "" };
        let protocol = if fd_type.contains("IPv6") || fd_type.contains('6') {
            "IPv6".to_string()
        } else {
            "IPv4".to_string()
        };

        let key = format!("{}:{}:{}:{}:{}", process_name, pid, port, address, protocol);
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);

        ports.push(PortInfo {
            port,
            protocol,
            address,
            pid,
            process: process_name,
            user,
            command: None,
        });
    }

    ports.sort_by_key(|p| p.port);
    ports
}

#[cfg(target_os = "linux")]
fn parse_ss_output(stdout: &str) -> Vec<PortInfo> {
    let mut ports = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { continue; }

        let local_addr = parts[3];
        let (address, port_str) = match local_addr.rfind(':') {
            Some(pos) => (&local_addr[..pos], &local_addr[pos + 1..]),
            None => continue,
        };

        let port: u16 = match port_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let (process, pid) = if parts.len() > 5 {
            parse_ss_process_info(parts[5])
        } else {
            ("-".to_string(), "-".to_string())
        };

        let protocol = if address.contains(':') { "IPv6" } else { "IPv4" }.to_string();
        let address = if address == "*" || address == "0.0.0.0" || address == "[::]" {
            "*".to_string()
        } else {
            address.to_string()
        };

        let key = format!("{}:{}:{}", port, address, protocol);
        if seen.contains(&key) { continue; }
        seen.insert(key);

        ports.push(PortInfo { port, protocol, address, pid, process, user: "-".to_string(), command: None });
    }

    ports.sort_by_key(|p| p.port);
    ports
}

#[cfg(target_os = "linux")]
fn parse_ss_process_info(info: &str) -> (String, String) {
    if let Some(start) = info.find("((\"") {
        if let Some(end) = info[start + 3..].find("\"") {
            let process = &info[start + 3..start + 3 + end];
            if let Some(pid_start) = info.find("pid=") {
                if let Some(pid_end) = info[pid_start + 4..].find(',') {
                    let pid = &info[pid_start + 4..pid_start + 4 + pid_end];
                    return (process.to_string(), pid.to_string());
                }
            }
            return (process.to_string(), "-".to_string());
        }
    }
    ("-".to_string(), "-".to_string())
}

#[cfg(target_os = "windows")]
fn parse_netstat_windows(stdout: &str) -> Vec<PortInfo> {
    let mut ports = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in stdout.lines() {
        if !line.contains("LISTENING") { continue; }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { continue; }

        let proto = parts[0];
        let local_addr = parts[1];
        let pid = parts[4];

        let (address, port_str) = match local_addr.rfind(':') {
            Some(pos) => (&local_addr[..pos], &local_addr[pos + 1..]),
            None => continue,
        };

        let port: u16 = match port_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let protocol = if proto.contains('6') { "IPv6" } else { "IPv4" }.to_string();
        let address = if address == "0.0.0.0" || address == "[::]" || address == "*" {
            "*".to_string()
        } else {
            address.to_string()
        };

        let process = get_process_name_windows(pid).unwrap_or_else(|| pid.to_string());
        let key = format!("{}:{}:{}", port, address, protocol);
        if seen.contains(&key) { continue; }
        seen.insert(key);

        ports.push(PortInfo { port, protocol, address, pid: pid.to_string(), process, user: "-".to_string(), command: None });
    }

    ports.sort_by_key(|p| p.port);
    ports
}

#[cfg(target_os = "windows")]
fn get_process_name_windows(pid: &str) -> Option<String> {
    let output = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
        .output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().next()?.split(',').next().map(|s| s.trim_matches('"').to_string())
}

/// 获取进程的完整命令行
pub fn get_process_command(pid: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("wmic")
            .args(["process", "where", &format!("ProcessId={}", pid), "get", "CommandLine", "/value"])
            .output().ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.starts_with("CommandLine=") {
                return Some(line[12..].trim().to_string());
            }
        }
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        let output = Command::new("ps").args(["-p", pid, "-o", "command="]).output().ok()?;
        let cmd = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if cmd.is_empty() { None } else { Some(cmd) }
    }
}

/// 扫描端口（带命令行选项）
pub fn scan_ports(include_command: bool) -> ScanResult {
    let mut ports = get_listening_ports_raw();

    if include_command {
        let mut cmd_cache: HashMap<String, Option<String>> = HashMap::new();
        for port in &mut ports {
            let cmd = cmd_cache.entry(port.pid.clone())
                .or_insert_with(|| get_process_command(&port.pid)).clone();
            port.command = cmd;
        }
    }

    let unique_apps: std::collections::HashSet<_> = ports.iter()
        .map(|p| format!("{}:{}", p.process, p.pid)).collect();

    ScanResult {
        scan_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        total_ports: ports.len(),
        unique_apps: unique_apps.len(),
        ports,
    }
}

/// 按应用分组
pub fn scan_ports_grouped() -> Vec<AppGroup> {
    let ports = get_listening_ports_raw();
    let mut groups: HashMap<(String, String), Vec<u16>> = HashMap::new();

    for port in &ports {
        groups.entry((port.process.clone(), port.pid.clone())).or_default().push(port.port);
    }

    let mut result: Vec<AppGroup> = groups.into_iter()
        .map(|((process, pid), mut port_list)| {
            port_list.sort();
            port_list.dedup();
            let command = get_process_command(&pid);
            AppGroup { process, pid, ports: port_list, command }
        }).collect();

    result.sort_by_key(|g| g.ports.first().copied().unwrap_or(0));
    result
}

/// 过滤端口
pub fn filter_ports(port_filter: Option<u16>, app_filter: Option<String>, exclude_system: bool) -> Vec<PortInfo> {
    let mut ports = get_listening_ports_raw();

    if let Some(pf) = port_filter {
        ports.retain(|p| p.port == pf);
    }
    if let Some(ref af) = app_filter {
        let af_lower = af.to_lowercase();
        ports.retain(|p| p.process.to_lowercase().contains(&af_lower));
    }
    if exclude_system {
        #[cfg(target_os = "macos")]
        let system_procs = ["controlce", "rapportd", "netdisk_s", "mds", "launchd"];
        #[cfg(target_os = "linux")]
        let system_procs = ["systemd", "sshd", "dbus", "networkmanager"];
        #[cfg(target_os = "windows")]
        let system_procs = ["system", "svchost", "lsass", "services"];
        ports.retain(|p| !system_procs.contains(&p.process.to_lowercase().as_str()));
    }
    ports
}
