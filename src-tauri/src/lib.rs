//! Portly - Tauri GUI 入口

mod core;

pub use core::*;

/// Tauri 命令: 扫描端口
#[tauri::command]
fn tauri_scan_ports(include_command: bool) -> ScanResult {
    core::scan_ports(include_command)
}

/// Tauri 命令: 按应用分组
#[tauri::command]
fn tauri_scan_ports_grouped() -> Vec<AppGroup> {
    core::scan_ports_grouped()
}

/// Tauri 命令: 过滤端口
#[tauri::command]
fn tauri_filter_ports(
    port_filter: Option<u16>,
    app_filter: Option<String>,
    exclude_system: bool,
) -> Vec<PortInfo> {
    core::filter_ports(port_filter, app_filter, exclude_system)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            tauri_scan_ports,
            tauri_scan_ports_grouped,
            tauri_filter_ports
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
