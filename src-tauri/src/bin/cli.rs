//! Portly CLI - 命令行端口扫描器

// 引用 lib crate
use portly_lib::{scan_ports, scan_ports_grouped, PortInfo, AppGroup};
use std::collections::HashSet;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    let mut json_output = false;
    let mut grouped = false;
    let mut show_command = false;
    let mut app_filter: Option<String> = None;
    let mut port_filter: Option<u16> = None;
    let mut exclude_system = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-j" | "--json" => json_output = true,
            "-g" | "--group" => grouped = true,
            "-c" | "--command" => show_command = true,
            "-x" | "--exclude-system" => exclude_system = true,
            "-f" | "--filter" => {
                if i + 1 < args.len() {
                    app_filter = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-p" | "--port" => {
                if i + 1 < args.len() {
                    port_filter = args[i + 1].parse().ok();
                    i += 1;
                }
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            _ => {}
        }
        i += 1;
    }
    
    if grouped {
        let groups = scan_ports_grouped();
        let filtered = apply_filter_groups(groups, &app_filter, exclude_system);
        
        if json_output {
            println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
        } else {
            print_groups(&filtered);
        }
    } else {
        let result = scan_ports(show_command);
        let filtered = apply_filter_ports(result.ports, port_filter, &app_filter, exclude_system);
        
        if json_output {
            let output = serde_json::json!({
                "scan_time": result.scan_time,
                "total_ports": filtered.len(),
                "ports": filtered
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            print_table(&filtered, show_command, &result.scan_time);
        }
    }
}

fn apply_filter_ports(mut ports: Vec<PortInfo>, port_filter: Option<u16>, app_filter: &Option<String>, exclude_system: bool) -> Vec<PortInfo> {
    if let Some(pf) = port_filter {
        ports.retain(|p| p.port == pf);
    }
    if let Some(ref af) = app_filter {
        let af_lower = af.to_lowercase();
        ports.retain(|p| p.process.to_lowercase().contains(&af_lower));
    }
    if exclude_system {
        #[cfg(target_os = "macos")]
        let system_procs: &[&str] = &["controlce", "rapportd", "netdisk_s", "mds", "launchd"];
        #[cfg(target_os = "linux")]
        let system_procs: &[&str] = &["systemd", "sshd", "dbus", "networkmanager"];
        #[cfg(target_os = "windows")]
        let system_procs: &[&str] = &["system", "svchost", "lsass", "services"];
        ports.retain(|p| !system_procs.contains(&p.process.to_lowercase().as_str()));
    }
    ports
}

fn apply_filter_groups(mut groups: Vec<AppGroup>, app_filter: &Option<String>, exclude_system: bool) -> Vec<AppGroup> {
    if let Some(ref af) = app_filter {
        let af_lower = af.to_lowercase();
        groups.retain(|g| g.process.to_lowercase().contains(&af_lower));
    }
    if exclude_system {
        #[cfg(target_os = "macos")]
        let system_procs: &[&str] = &["controlce", "rapportd", "netdisk_s", "mds", "launchd"];
        #[cfg(target_os = "linux")]
        let system_procs: &[&str] = &["systemd", "sshd", "dbus", "networkmanager"];
        #[cfg(target_os = "windows")]
        let system_procs: &[&str] = &["system", "svchost", "lsass", "services"];
        groups.retain(|g| !system_procs.contains(&g.process.to_lowercase().as_str()));
    }
    groups
}

fn print_help() {
    println!(r#"
🔍 Portly CLI - 跨平台端口扫描器 / Cross-platform port scanner

用法 / Usage: portly-cli [OPTIONS]

选项 / Options:
  -j, --json           JSON 格式输出 / JSON output
  -g, --group          按应用分组显示 / Group by application
  -c, --command        显示进程命令行 / Show command line
  -x, --exclude-system 排除系统进程 / Exclude system processes
  -f, --filter <APP>   按应用名过滤 / Filter by app name
  -p, --port <PORT>    按端口号过滤 / Filter by port
  -h, --help           显示帮助信息 / Show help

示例 / Examples:
  portly-cli                    # 列出所有端口 / List all ports
  portly-cli -g                 # 按应用分组 / Group by app
  portly-cli -j                 # JSON 输出 / JSON output
  portly-cli -f docker          # 过滤 docker 相关 / Filter docker
  portly-cli -p 8080            # 只显示端口 8080 / Show port 8080
  portly-cli -c -x              # 显示命令行，排除系统进程 / With command, no system
"#);
}

fn print_table(ports: &[PortInfo], show_command: bool, scan_time: &str) {
    let unique_apps: HashSet<_> = ports.iter().map(|p| format!("{}:{}", p.process, p.pid)).collect();
    
    println!();
    println!("═══════════════════════════════════════════════════════════════════════════════");
    println!("  🔍 Portly - {}", scan_time);
    println!("═══════════════════════════════════════════════════════════════════════════════");
    println!();
    println!("  📊 {} 个应用 | {} 个端口", unique_apps.len(), ports.len());
    println!();
    println!("  {:>6}  {:^5}  {:^18}  {:>7}  {:<18}  {}", "端口", "协议", "监听地址", "PID", "应用程序", "用户");
    println!("  {}", "─".repeat(75));
    
    for p in ports {
        let addr = if p.address.len() > 18 { format!("{}...", &p.address[..15]) } else { p.address.clone() };
        let proc = if p.process.len() > 18 { format!("{}...", &p.process[..15]) } else { p.process.clone() };
        
        println!("  {:>6}  {:^5}  {:^18}  {:>7}  {:<18}  {}", p.port, p.protocol, addr, p.pid, proc, p.user);
        
        if show_command {
            if let Some(ref cmd) = p.command {
                let cmd_display: String = if cmd.len() > 68 { format!("{}...", &cmd[..65]) } else { cmd.clone() };
                println!("         └─ {}", cmd_display);
            }
        }
    }
    
    println!();
    println!("═══════════════════════════════════════════════════════════════════════════════");
}

fn print_groups(groups: &[AppGroup]) {
    println!();
    println!("═══════════════════════════════════════════════════════════════════════════════");
    println!("  🔍 Portly - 按应用分组");
    println!("═══════════════════════════════════════════════════════════════════════════════");
    println!();
    
    for g in groups {
        let ports_str: String = g.ports.iter().map(|p: &u16| p.to_string()).collect::<Vec<_>>().join(", ");
        println!("  📦 {} (PID: {})", g.process, g.pid);
        println!("     └─ 端口: {}", ports_str);
        if let Some(ref cmd) = g.command {
            let cmd_display: String = if cmd.len() > 60 { format!("{}...", &cmd[..57]) } else { cmd.clone() };
            println!("     └─ 命令: {}", cmd_display);
        }
        println!();
    }
    
    println!("═══════════════════════════════════════════════════════════════════════════════");
}
