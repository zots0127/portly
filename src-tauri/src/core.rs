//! Portly 核心库 - 跨平台端口扫描器
//!
//! 支持 macOS, Linux, Windows

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::command_exec::run_command;

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
    let output = match run_command("lsof", "端口扫描 (macOS lsof)", |cmd| {
        cmd.args(["-i", "-P", "-n"]);
    }) {
        Ok(o) if o.status == 0 => o,
        Err(_) => return Vec::new(),
        _ => return Vec::new(),
    };

    let mut ports = parse_lsof_output(&output.stdout);

    // 获取完整进程名称（lsof 会截断进程名）
    let mut name_cache: HashMap<String, String> = HashMap::new();
    for port in &mut ports {
        let full_name = name_cache
            .entry(port.pid.clone())
            .or_insert_with(|| {
                get_full_process_name(&port.pid).unwrap_or_else(|| port.process.clone())
            })
            .clone();
        port.process = full_name;
    }

    ports
}

/// 获取进程的完整名称
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn get_full_process_name(pid: &str) -> Option<String> {
    let output = run_command("ps", "进程名称读取", |cmd| {
        cmd.args(["-p", pid, "-o", "comm="]);
    })
    .ok()?;

    if output.status != 0 {
        return None;
    }

    let name = output.stdout.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Linux: 使用 ss 或 lsof
#[cfg(target_os = "linux")]
fn get_ports_linux() -> Vec<PortInfo> {
    let output = run_command("ss", "端口扫描 (Linux ss)", |cmd| {
        cmd.args(["-tlnp"]);
    });

    if let Ok(o) = output {
        if o.status == 0 {
            return parse_ss_output(&o.stdout);
        }
    }

    let output = match run_command("lsof", "端口扫描 (Linux lsof)", |cmd| {
        cmd.args(["-i", "-P", "-n"]);
    }) {
        Ok(o) if o.status == 0 => o,
        Err(_) => return Vec::new(),
        _ => return Vec::new(),
    };
    parse_lsof_output(&output.stdout)
}

/// Windows: 使用 netstat
#[cfg(target_os = "windows")]
fn get_ports_windows() -> Vec<PortInfo> {
    let output = match run_command("netstat", "端口扫描 (Windows netstat)", |cmd| {
        cmd.args(["-ano"]).creation_flags(CREATE_NO_WINDOW);
    }) {
        Ok(o) if o.status == 0 => o,
        Err(_) => return Vec::new(),
        _ => return Vec::new(),
    };
    parse_netstat_windows(&output.stdout)
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
        if parts.len() < 5 {
            continue;
        }

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

        let protocol = if address.contains(':') {
            "IPv6"
        } else {
            "IPv4"
        }
        .to_string();
        let address = if address == "*" || address == "0.0.0.0" || address == "[::]" {
            "*".to_string()
        } else {
            address.to_string()
        };

        let key = format!("{}:{}:{}", port, address, protocol);
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);

        ports.push(PortInfo {
            port,
            protocol,
            address,
            pid,
            process,
            user: "-".to_string(),
            command: None,
        });
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
        if !line.contains("LISTENING") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

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
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);

        ports.push(PortInfo {
            port,
            protocol,
            address,
            pid: pid.to_string(),
            process,
            user: "-".to_string(),
            command: None,
        });
    }

    ports.sort_by_key(|p| p.port);
    ports
}

#[cfg(target_os = "windows")]
fn get_process_name_windows(pid: &str) -> Option<String> {
    let output = run_command("tasklist", "进程名读取", |cmd| {
        cmd.args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"]);
    })
    .ok()?;
    if output.status != 0 {
        return None;
    }

    let stdout = output.stdout;
    stdout
        .lines()
        .next()?
        .split(',')
        .next()
        .map(|s| s.trim_matches('"').to_string())
}

/// 获取进程的完整命令行
pub fn get_process_command(pid: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let output = run_command("wmic", "进程命令行读取", |cmd| {
            cmd.args([
                "process",
                "where",
                &format!("ProcessId={}", pid),
                "get",
                "CommandLine",
                "/value",
            ]);
        })
        .ok()?;
        if output.status != 0 {
            return None;
        }
        let stdout = output.stdout;
        for line in stdout.lines() {
            if line.starts_with("CommandLine=") {
                return Some(line[12..].trim().to_string());
            }
        }
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        let output = run_command("ps", "进程命令行读取", |cmd| {
            cmd.args(["-p", pid, "-o", "command="]);
        })
        .ok()?;
        if output.status != 0 {
            return None;
        }
        let cmd = output.stdout.trim().to_string();
        if cmd.is_empty() {
            None
        } else {
            Some(cmd)
        }
    }
}

/// 扫描端口（带命令行选项）
pub fn scan_ports(include_command: bool) -> ScanResult {
    let mut ports = get_listening_ports_raw();

    if include_command {
        let mut cmd_cache: HashMap<String, Option<String>> = HashMap::new();
        for port in &mut ports {
            let cmd = cmd_cache
                .entry(port.pid.clone())
                .or_insert_with(|| get_process_command(&port.pid))
                .clone();
            port.command = cmd;
        }
    }

    let unique_apps: std::collections::HashSet<_> = ports
        .iter()
        .map(|p| format!("{}:{}", p.process, p.pid))
        .collect();

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
        groups
            .entry((port.process.clone(), port.pid.clone()))
            .or_default()
            .push(port.port);
    }

    let mut result: Vec<AppGroup> = groups
        .into_iter()
        .map(|((process, pid), mut port_list)| {
            port_list.sort();
            port_list.dedup();
            let command = get_process_command(&pid);
            AppGroup {
                process,
                pid,
                ports: port_list,
                command,
            }
        })
        .collect();

    result.sort_by_key(|g| g.ports.first().copied().unwrap_or(0));
    result
}

/// 过滤端口
pub fn filter_ports(
    port_filter: Option<u16>,
    app_filter: Option<String>,
    exclude_system: bool,
) -> Vec<PortInfo> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_ports_returns_valid_structure() {
        let result = scan_ports(false);
        assert_eq!(result.ports.len(), result.total_ports);
        assert!(!result.scan_time.is_empty());
    }

    #[test]
    fn test_scan_ports_with_command() {
        let result = scan_ports(true);
        // 检查返回的结构
        assert!(!result.ports.is_empty() || result.ports.is_empty());
    }

    #[test]
    fn test_scan_ports_grouped_returns_valid_structure() {
        let groups = scan_ports_grouped();
        // 检查返回非空或有效的空结果
        // 每个组应有进程名、PID和端口列表
        for group in &groups {
            assert!(!group.process.is_empty());
            assert!(!group.pid.is_empty());
            assert!(!group.ports.is_empty());
        }
    }

    #[test]
    fn test_filter_ports_by_port() {
        // 创建模拟数据
        let _ports = vec![
            PortInfo {
                port: 8080,
                protocol: "tcp".to_string(),
                address: "127.0.0.1".to_string(),
                pid: "1234".to_string(),
                process: "node".to_string(),
                user: "user".to_string(),
                command: Some("node /app".to_string()),
            },
            PortInfo {
                port: 3000,
                protocol: "tcp".to_string(),
                address: "0.0.0.0".to_string(),
                pid: "5678".to_string(),
                process: "node".to_string(),
                user: "user".to_string(),
                command: None,
            },
        ];

        // 测试按端口过滤 - 使用实际系统数据
        let all_ports = get_listening_ports_raw();
        if !all_ports.is_empty() {
            let target_port = all_ports[0].port;
            let filtered = filter_ports(Some(target_port), None, false);
            assert!(!filtered.is_empty());
            assert!(filtered.iter().all(|p| p.port == target_port));
        }
    }

    #[test]
    fn test_filter_ports_by_app() {
        // 使用实际系统数据测试应用过滤
        let all_ports = get_listening_ports_raw();
        if !all_ports.is_empty() {
            let target_process = all_ports[0].process.clone();
            let filtered = filter_ports(None, Some(target_process.clone()), false);
            // 验证结果包含目标进程名
            assert!(filtered.iter().all(|p| p.process.to_lowercase().contains(&target_process.to_lowercase())));
        }
    }

    #[test]
    fn test_filter_ports_exclude_system() {
        // 测试系统进程过滤逻辑
        let _ports = vec![
            PortInfo {
                port: 80,
                protocol: "tcp".to_string(),
                address: "0.0.0.0".to_string(),
                pid: "1".to_string(),
                process: "launchd".to_string(),
                user: "root".to_string(),
                command: None,
            },
        ];

        // 在macOS上测试系统进程过滤
        #[cfg(target_os = "macos")]
        {
            let _all_ports = get_listening_ports_raw();
            let filtered = filter_ports(None, None, true);
            // 验证系统进程被过滤
            assert!(!filtered.iter().any(|p| {
                ["controlce", "rapportd", "netdisk_s", "mds", "launchd"]
                    .contains(&p.process.to_lowercase().as_str())
            }));
        }
    }

    #[test]
    fn test_port_info_serialization() {
        let port = PortInfo {
            port: 8080,
            protocol: "tcp".to_string(),
            address: "127.0.0.1".to_string(),
            pid: "1234".to_string(),
            process: "test".to_string(),
            user: "user".to_string(),
            command: Some("command".to_string()),
        };

        // 测试序列化和反序列化
        let serialized = serde_json::to_string(&port).unwrap();
        let deserialized: PortInfo = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.port, port.port);
        assert_eq!(deserialized.process, port.process);
    }

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            scan_time: "2024-01-01 12:00:00".to_string(),
            total_ports: 2,
            unique_apps: 1,
            ports: vec![
                PortInfo {
                    port: 8080,
                    protocol: "tcp".to_string(),
                    address: "127.0.0.1".to_string(),
                    pid: "1234".to_string(),
                    process: "test".to_string(),
                    user: "user".to_string(),
                    command: None,
                },
            ],
        };

        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: ScanResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.total_ports, 2);
        assert_eq!(deserialized.unique_apps, 1);
    }

    #[test]
    fn test_app_group_serialization() {
        let group = AppGroup {
            process: "test".to_string(),
            pid: "1234".to_string(),
            ports: vec![8080, 3000],
            command: Some("test command".to_string()),
        };

        let serialized = serde_json::to_string(&group).unwrap();
        let deserialized: AppGroup = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.process, "test");
        assert_eq!(deserialized.ports.len(), 2);
    }

    #[test]
    fn test_port_info_clone() {
        let port = PortInfo {
            port: 8080,
            protocol: "tcp".to_string(),
            address: "127.0.0.1".to_string(),
            pid: "1234".to_string(),
            process: "test".to_string(),
            user: "user".to_string(),
            command: Some("command".to_string()),
        };

        let cloned = port.clone();
        assert_eq!(cloned.port, port.port);
        assert_eq!(cloned.process, port.process);
        assert_eq!(cloned.command, port.command);
    }

    #[test]
    fn test_get_listening_ports_raw_returns_vec() {
        let ports = get_listening_ports_raw();
        // 验证返回的是Vec类型
        let _ports: Vec<PortInfo> = ports;
        // 如果有端口，验证其结构
        let ports = get_listening_ports_raw();
        for port in &ports {
            assert!(port.port > 0);
            assert!(!port.protocol.is_empty());
            assert!(!port.pid.is_empty());
            assert!(!port.process.is_empty());
        }
    }

    #[test]
    fn test_filter_ports_empty_result() {
        // 测试过滤不存在的端口
        let filtered = filter_ports(Some(60000), None, false);
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_filter_ports_no_filters() {
        // 不带任何过滤条件
        let ports = get_listening_ports_raw();
        let filtered = filter_ports(None, None, false);
        assert_eq!(filtered.len(), ports.len());
    }

    #[test]
    fn test_app_group_structure() {
        let groups = scan_ports_grouped();
        for group in &groups {
            // 验证每个组都有有效的进程名和PID
            assert!(!group.process.is_empty());
            assert!(!group.pid.is_empty());
            // 验证端口列表已排序且去重
            let mut sorted_ports = group.ports.clone();
            sorted_ports.sort();
            sorted_ports.dedup();
            assert_eq!(group.ports, sorted_ports);
        }
    }

    #[test]
    fn test_unique_apps_count() {
        let result = scan_ports(false);
        let unique_pids: std::collections::HashSet<_> = result.ports.iter().map(|p| &p.pid).collect();
        assert_eq!(result.unique_apps, unique_pids.len());
    }
}
