//! Process management module for Portly
//! Provides cross-platform process termination capabilities

use serde::{Deserialize, Serialize};
use crate::command_exec::run_command;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

// Windows CREATE_NO_WINDOW flag to hide console windows
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

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
    PROTECTED_PROCESSES
        .iter()
        .any(|p| name_lower.contains(&p.to_lowercase()))
}

/// Get process information by PID
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    let pid_number = pid;
    let pid = pid.to_string();
    let output = run_command("ps", "进程信息查询", |cmd| {
        cmd.args(["-p", pid.as_str(), "-o", "comm="]);
    })
    .ok()?;
    if output.status != 0 {
        return None;
    }

    let name = output.stdout.trim().to_string();
    if name.is_empty() {
        return None;
    }

    Some(ProcessInfo {
        pid: pid_number,
        name: name.clone(),
        is_system: is_protected_process(&name),
    })
}

#[cfg(target_os = "windows")]
pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    let pid_filter = format!("PID eq {}", pid);
    let output = run_command("tasklist", "进程信息查询", |cmd| {
        cmd.args(["/FI", pid_filter.as_str(), "/FO", "CSV", "/NH"])
            .creation_flags(CREATE_NO_WINDOW);
    })
    .ok()?;
    if output.status != 0 {
        return None;
    }

    let stdout = output.stdout;
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
    let pid_number = pid;
    let pid = pid_number.to_string();
    let output = run_command("kill", "进程终止", |cmd| {
        cmd.args([signal, pid.as_str()]);
    });

    match output {
        Ok(result) => {
            if result.status == 0 {
                KillResult {
                    success: true,
                    pid: pid_number,
                    message: format!("进程 {} 已{}终止", pid, if force { "强制" } else { "" }),
                }
            } else {
                KillResult {
                    success: false,
                    pid: pid_number,
                    message: format!(
                        "终止进程失败: {}",
                        result.stderr.trim()
                    ),
                }
            }
        }
        Err(e) => KillResult {
            success: false,
            pid: pid_number,
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
    let pid_num = pid;
    let mut args: Vec<&str> = vec!["/PID", pid_str.as_str()];
    if force {
        args.push("/F");
    }

    let output = run_command("taskkill", "进程终止", |cmd| {
        cmd.args(&args).creation_flags(CREATE_NO_WINDOW);
    });

    match output {
        Ok(result) => {
            if result.status == 0 {
                KillResult {
                    success: true,
                    pid: pid_num,
                    message: format!(
                        "Process {} terminated{}",
                        pid_num,
                        if force { " (forced)" } else { "" }
                    ),
                }
            } else {
                KillResult {
                    success: false,
                    pid: pid_num,
                    message: format!("Failed to terminate process: {}", result.stderr.trim()),
                }
            }
        }
        Err(e) => KillResult {
            success: false,
            pid: pid_num,
            message: format!("Failed to execute taskkill: {}", e),
        },
    }
}

/// Try to kill a process blocking a specific port
pub fn kill_port_process(port: u16) -> KillResult {
    // Find the process using this port
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let target = format!(":{}", port);
        let output = run_command("lsof", "端口占用查询", |cmd| {
            cmd.args(["-ti", target.as_str()]);
        });

        match output {
            Ok(result) => {
                let pids: Vec<u32> = result
                    .stdout
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
        let output = run_command("netstat", "端口占用查询", |cmd| {
            cmd.args(["-ano"]).creation_flags(CREATE_NO_WINDOW);
        });

        match output {
            Ok(result) => {
                let port_str = format!(":{}", port);

                let pids: Vec<u32> = result
                    .stdout
                    .lines()
                    .filter(|line| line.contains(&port_str) && line.contains("LISTENING"))
                    .filter_map(|line| line.split_whitespace().last().and_then(|s| s.parse().ok()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_info_serialization() {
        let info = ProcessInfo {
            pid: 1234,
            name: "test".to_string(),
            is_system: false,
        };

        let serialized = serde_json::to_string(&info).unwrap();
        let deserialized: ProcessInfo = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.pid, 1234);
        assert_eq!(deserialized.name, "test");
        assert!(!deserialized.is_system);
    }

    #[test]
    fn test_kill_result_serialization() {
        let result = KillResult {
            success: true,
            pid: 1234,
            message: "Process terminated".to_string(),
        };

        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: KillResult = serde_json::from_str(&serialized).unwrap();
        assert!(deserialized.success);
        assert_eq!(deserialized.pid, 1234);
    }

    #[test]
    fn test_is_protected_process_identifies_system_processes() {
        // 测试系统进程识别（平台相关）
        #[cfg(target_os = "macos")]
        {
            assert!(is_protected_process("launchd"));
            assert!(is_protected_process("kernel_task"));
            assert!(is_protected_process("WindowServer"));
            assert!(!is_protected_process("Chrome"));
            assert!(!is_protected_process("MyApp"));
        }

        #[cfg(target_os = "linux")]
        {
            assert!(is_protected_process("systemd"));
            assert!(is_protected_process("init"));
            assert!(is_protected_process("dbus-daemon"));
            assert!(!is_protected_process("nginx"));
            assert!(!is_protected_process("MyApp"));
        }

        #[cfg(target_os = "windows")]
        {
            assert!(is_protected_process("System"));
            assert!(is_protected_process("svchost.exe"));
            assert!(is_protected_process("csrss.exe"));
            assert!(!is_protected_process("chrome.exe"));
            assert!(!is_protected_process("MyApp.exe"));
        }
    }

    #[test]
    fn test_is_protected_process_case_insensitive() {
        // 测试不区分大小写
        assert!(is_protected_process("LAUNCHD"));
        assert!(is_protected_process("Systemd"));
        assert!(is_protected_process("SYSTEM"));
        assert!(is_protected_process("SVCHOST.EXE"));
    }

    #[test]
    fn test_process_info_with_system_flag() {
        let system_info = ProcessInfo {
            pid: 1,
            name: "launchd".to_string(),
            is_system: true,
        };

        assert!(system_info.is_system);
        assert_eq!(system_info.pid, 1);

        let user_info = ProcessInfo {
            pid: 1234,
            name: "chrome".to_string(),
            is_system: false,
        };

        assert!(!user_info.is_system);
    }

    #[test]
    fn test_kill_result_fields() {
        let success_result = KillResult {
            success: true,
            pid: 5678,
            message: "进程已终止".to_string(),
        };

        assert!(success_result.success);
        assert_eq!(success_result.pid, 5678);
        assert_eq!(success_result.message, "进程已终止");

        let failure_result = KillResult {
            success: false,
            pid: 9999,
            message: "权限不足".to_string(),
        };

        assert!(!failure_result.success);
        assert_eq!(failure_result.pid, 9999);
        assert_eq!(failure_result.message, "权限不足");
    }

    #[test]
    fn test_protected_processes_list_not_empty() {
        assert!(!PROTECTED_PROCESSES.is_empty());
        assert!(PROTECTED_PROCESSES.len() > 10);
    }

    #[test]
    fn test_common_system_processes_in_list() {
        // 验证常见系统进程在保护列表中
        let protected_set: std::collections::HashSet<&str> =
            PROTECTED_PROCESSES.iter().cloned().collect();

        #[cfg(target_os = "macos")]
        {
            assert!(protected_set.contains(&"launchd"));
            assert!(protected_set.contains(&"WindowServer"));
        }

        #[cfg(target_os = "linux")]
        {
            assert!(protected_set.contains(&"systemd"));
            assert!(protected_set.contains(&"init"));
        }

        #[cfg(target_os = "windows")]
        {
            assert!(protected_set.contains(&"System"));
            assert!(protected_set.contains(&"svchost.exe"));
        }
    }

    #[test]
    fn test_process_info_clone() {
        let info1 = ProcessInfo {
            pid: 1111,
            name: "test_process".to_string(),
            is_system: false,
        };

        let info2 = info1.clone();

        assert_eq!(info1.pid, info2.pid);
        assert_eq!(info1.name, info2.name);
        assert_eq!(info1.is_system, info2.is_system);
    }

    #[test]
    fn test_kill_result_clone() {
        let result1 = KillResult {
            success: false,
            pid: 2222,
            message: "测试消息".to_string(),
        };

        let result2 = result1.clone();

        assert_eq!(result1.success, result2.success);
        assert_eq!(result1.pid, result2.pid);
        assert_eq!(result1.message, result2.message);
    }

    #[test]
    fn test_partial_name_match() {
        // 测试部分名称匹配（contains 逻辑）
        // 函数检查 process name 是否包含 protected process 名称
        assert!(is_protected_process("launchd")); // 完全匹配 launchd
        assert!(is_protected_process("WindowServer")); // 完全匹配 WindowServer
        assert!(!is_protected_process("my-custom-app")); // 不匹配任何保护进程

        // 测试包含关系 - 如果进程名包含保护进程名，则被保护
        #[cfg(target_os = "windows")]
        {
            assert!(is_protected_process("svchost.exe"));
        }
    }
}
