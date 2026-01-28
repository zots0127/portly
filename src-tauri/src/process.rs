//! Process management module for Portly
//! Provides cross-platform process termination capabilities

use serde::{Deserialize, Serialize};
use std::process::Command;

/// Result of a process kill operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillResult {
    pub success: bool,
    pub pid: u32,
    pub message: String,
}

/// Information about a process before killing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub is_system: bool,
}

/// List of system-critical processes that should NOT be killed
const PROTECTED_PROCESSES: &[&str] = &[
    "launchd",
    "kernel_task",
    "WindowServer",
    "loginwindow",
    "SystemUIServer",
    "Finder",
    "Dock",
    "cfprefsd",
    "mds",
    "mds_stores",
    "init",
    "systemd",
    "dbus-daemon",
    "gnome-shell",
    "kwin",
    // Windows
    "System",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
];

/// Check if a process is a protected system process
pub fn is_protected_process(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    PROTECTED_PROCESSES.iter().any(|p| name_lower.contains(&p.to_lowercase()))
}

/// Get process information by PID
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if name.is_empty() {
        return None;
    }
    
    Some(ProcessInfo {
        pid,
        name: name.clone(),
        is_system: is_protected_process(&name),
    })
}

#[cfg(target_os = "windows")]
pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    let output = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
        .output()
        .ok()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse CSV: "name.exe","PID","Session Name","Session#","Mem Usage"
    let parts: Vec<&str> = stdout.trim().split(',').collect();
    if parts.is_empty() {
        return None;
    }
    
    let name = parts[0].trim_matches('"').to_string();
    if name.is_empty() || name.contains("INFO:") {
        return None;
    }
    
    Some(ProcessInfo {
        pid,
        name: name.clone(),
        is_system: is_protected_process(&name),
    })
}

/// Kill a process by PID (Unix: macOS/Linux)
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn kill_process(pid: u32, force: bool) -> KillResult {
    // First, check if process exists and is safe to kill
    if let Some(info) = get_process_info(pid) {
        if info.is_system && !force {
            return KillResult {
                success: false,
                pid,
                message: format!(
                    "进程 '{}' (PID: {}) 是受保护的系统进程。如需强制终止，请使用强制模式。",
                    info.name, pid
                ),
            };
        }
    }
    
    // Try graceful SIGTERM first
    let signal = if force { "-9" } else { "-15" };
    let output = Command::new("kill")
        .args([signal, &pid.to_string()])
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                KillResult {
                    success: true,
                    pid,
                    message: format!(
                        "进程 {} 已{}终止",
                        pid,
                        if force { "强制" } else { "" }
                    ),
                }
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr);
                KillResult {
                    success: false,
                    pid,
                    message: format!("终止进程失败: {}", stderr.trim()),
                }
            }
        }
        Err(e) => KillResult {
            success: false,
            pid,
            message: format!("执行 kill 命令失败: {}", e),
        },
    }
}

/// Kill a process by PID (Windows)
#[cfg(target_os = "windows")]
pub fn kill_process(pid: u32, force: bool) -> KillResult {
    // Check if process exists and is safe to kill
    if let Some(info) = get_process_info(pid) {
        if info.is_system && !force {
            return KillResult {
                success: false,
                pid,
                message: format!(
                    "Process '{}' (PID: {}) is a protected system process. Use force mode to override.",
                    info.name, pid
                ),
            };
        }
    }
    
    let pid_str = pid.to_string();
    let mut args = vec!["/PID", &pid_str];
    if force {
        args.push("/F");
    }
    
    let output = Command::new("taskkill")
        .args(&args)
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                KillResult {
                    success: true,
                    pid,
                    message: format!(
                        "Process {} terminated{}",
                        pid,
                        if force { " (forced)" } else { "" }
                    ),
                }
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr);
                KillResult {
                    success: false,
                    pid,
                    message: format!("Failed to terminate process: {}", stderr.trim()),
                }
            }
        }
        Err(e) => KillResult {
            success: false,
            pid,
            message: format!("Failed to execute taskkill: {}", e),
        },
    }
}

/// Try to kill a process blocking a specific port
pub fn kill_port_process(port: u16) -> KillResult {
    // Find the process using this port
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let output = Command::new("lsof")
            .args(["-ti", &format!(":{}", port)])
            .output();
        
        match output {
            Ok(result) => {
                let pids: Vec<u32> = String::from_utf8_lossy(&result.stdout)
                    .lines()
                    .filter_map(|line| line.trim().parse().ok())
                    .collect();
                
                if pids.is_empty() {
                    return KillResult {
                        success: false,
                        pid: 0,
                        message: format!("端口 {} 上未找到占用进程", port),
                    };
                }
                
                // Kill all processes on this port
                let mut all_success = true;
                let mut messages = Vec::new();
                
                for pid in pids {
                    let result = kill_process(pid, false);
                    if !result.success {
                        all_success = false;
                    }
                    messages.push(result.message);
                }
                
                KillResult {
                    success: all_success,
                    pid: 0, // Multiple PIDs
                    message: messages.join("; "),
                }
            }
            Err(e) => KillResult {
                success: false,
                pid: 0,
                message: format!("查找端口进程失败: {}", e),
            },
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        // Use netstat to find PID
        let output = Command::new("netstat")
            .args(["-ano"])
            .output();
        
        match output {
            Ok(result) => {
                let stdout = String::from_utf8_lossy(&result.stdout);
                let port_str = format!(":{}", port);
                
                let pids: Vec<u32> = stdout
                    .lines()
                    .filter(|line| line.contains(&port_str) && line.contains("LISTENING"))
                    .filter_map(|line| {
                        line.split_whitespace()
                            .last()
                            .and_then(|s| s.parse().ok())
                    })
                    .collect();
                
                if pids.is_empty() {
                    return KillResult {
                        success: false,
                        pid: 0,
                        message: format!("No process found on port {}", port),
                    };
                }
                
                let mut all_success = true;
                let mut messages = Vec::new();
                
                for pid in pids {
                    let result = kill_process(pid, false);
                    if !result.success {
                        all_success = false;
                    }
                    messages.push(result.message);
                }
                
                KillResult {
                    success: all_success,
                    pid: 0,
                    message: messages.join("; "),
                }
            }
            Err(e) => KillResult {
                success: false,
                pid: 0,
                message: format!("Failed to find port process: {}", e),
            },
        }
    }
}
