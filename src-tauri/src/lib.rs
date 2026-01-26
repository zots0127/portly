//! Portly - Tauri GUI 入口

mod core;
mod network;
mod advanced_scan;
mod docker;

pub use core::*;
pub use network::*;
pub use docker::*;

use tokio::task::spawn_blocking;

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

// ===== 网络扫描命令 =====

/// Tauri 命令: 获取本机网络接口
#[tauri::command]
fn tauri_get_interfaces() -> Vec<network::NetworkInterface> {
    network::get_local_interfaces()
}

/// Tauri 命令: 获取当前子网
#[tauri::command]
fn tauri_get_current_subnet() -> Option<String> {
    network::get_current_subnet()
}

/// Tauri 命令: 发现局域网设备（异步）
#[tauri::command]
async fn tauri_discover_devices(subnet: String) -> Vec<network::NetworkDevice> {
    spawn_blocking(move || network::discover_devices(&subnet))
        .await
        .unwrap_or_default()
}

/// Tauri 命令: 智能扫描（异步）
#[tauri::command]
async fn tauri_smart_scan(subnet: String) -> advanced_scan::AdvancedScanResult {
    spawn_blocking(move || advanced_scan::smart_scan(&subnet))
        .await
        .unwrap_or_else(|_| advanced_scan::AdvancedScanResult {
            devices: vec![],
            scan_method: "Error".to_string(),
            scan_time_ms: 0,
            has_permission: false,
        })
}

/// Tauri 命令: 检查是否有高级扫描权限
#[tauri::command]
fn tauri_check_permission() -> bool {
    advanced_scan::check_raw_socket_permission()
}

/// Tauri 命令: 快速端口扫描（异步）
#[tauri::command]
async fn tauri_quick_scan(ip: String) -> Vec<network::RemotePort> {
    spawn_blocking(move || network::quick_scan(&ip))
        .await
        .unwrap_or_default()
}

/// Tauri 命令: 自定义端口扫描（异步）
#[tauri::command]
async fn tauri_scan_ports_range(ip: String, start: u16, end: u16, timeout_ms: u64) -> Vec<network::RemotePort> {
    spawn_blocking(move || network::full_scan(&ip, start, end, timeout_ms))
        .await
        .unwrap_or_default()
}

/// Tauri 命令: 获取常用端口列表
#[tauri::command]
fn tauri_get_common_ports() -> Vec<u16> {
    network::get_common_ports()
}

/// Tauri 命令: Ping 测试（异步）
#[tauri::command]
async fn tauri_ping(ip: String, count: u32) -> network::PingResult {
    let ip_clone = ip.clone();
    spawn_blocking(move || network::ping_test(&ip_clone, count))
        .await
        .unwrap_or_else(|_| network::PingResult {
            ip,
            is_reachable: false,
            packets_sent: count,
            packets_received: 0,
            packet_loss: 100.0,
            min_ms: None,
            avg_ms: None,
            max_ms: None,
            raw_output: "Error".to_string(),
        })
}

/// Tauri 命令: 单次 Ping（异步，用于流式显示）
#[tauri::command]
async fn tauri_ping_one(ip: String, seq: u32) -> network::PingOneResult {
    let ip_clone = ip.clone();
    spawn_blocking(move || network::ping_one(&ip_clone, seq))
        .await
        .unwrap_or_else(|_| network::PingOneResult {
            ip,
            seq,
            success: false,
            time_ms: None,
            ttl: None,
            line: "Error".to_string(),
        })
}

/// Tauri 命令: Traceroute（异步）
#[tauri::command]
async fn tauri_traceroute(ip: String) -> network::TracerouteResult {
    let ip_clone = ip.clone();
    spawn_blocking(move || network::traceroute(&ip_clone))
        .await
        .unwrap_or_else(|_| network::TracerouteResult {
            target: ip,
            hops: vec![],
            raw_output: "Error".to_string(),
        })
}

/// Tauri 命令: 探测服务类型（异步）
#[tauri::command]
async fn tauri_detect_service(ip: String, port: u16) -> network::ServiceInfo {
    spawn_blocking(move || network::detect_service_type(&ip, port))
        .await
        .unwrap_or_else(|_| network::ServiceInfo {
            port,
            service: "Error".to_string(),
            service_type: "other".to_string(),
            server: None,
            content_type: None,
        })
}

/// Tauri 命令: 批量探测服务（异步）
#[tauri::command]
async fn tauri_detect_services(ip: String, ports: Vec<u16>) -> Vec<network::ServiceInfo> {
    spawn_blocking(move || network::detect_services(&ip, &ports))
        .await
        .unwrap_or_default()
}

// ===== Docker 命令 =====

/// Tauri 命令: 检查 Docker 是否可用
#[tauri::command]
fn tauri_docker_available() -> bool {
    docker::is_docker_available()
}

/// Tauri 命令: 获取 Docker 容器列表
#[tauri::command]
fn tauri_get_docker_containers() -> Vec<docker::DockerContainer> {
    docker::get_docker_containers()
}

/// Tauri 命令: 获取端口的容器信息
#[tauri::command]
fn tauri_get_docker_port_info(port: u16) -> Option<(String, String)> {
    docker::get_docker_port_info(port)
}

/// Tauri 命令: 解析 IP 或域名
#[tauri::command]
fn tauri_resolve_target(target: String) -> Result<network::ResolveResult, String> {
    network::resolve_target(&target)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            tauri_scan_ports,
            tauri_scan_ports_grouped,
            tauri_filter_ports,
            // 网络扫描
            tauri_get_interfaces,
            tauri_get_current_subnet,
            tauri_discover_devices,
            tauri_smart_scan,
            tauri_check_permission,
            tauri_quick_scan,
            tauri_scan_ports_range,
            tauri_get_common_ports,
            // 连通性测试
            tauri_ping,
            tauri_ping_one,
            tauri_traceroute,
            // 服务探测
            tauri_detect_service,
            tauri_detect_services,
            // Docker
            tauri_docker_available,
            tauri_get_docker_containers,
            tauri_get_docker_port_info,
            // IP/域名解析
            tauri_resolve_target
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
