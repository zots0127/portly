//! Portly - Tauri GUI 入口

mod app_error;
mod command_exec;
mod advanced_scan;
mod core;
mod dns;
mod docker;
mod export;
mod network;
mod process;
mod ssl;
mod whois;

pub use core::*;
pub use dns::*;
pub use docker::*;
pub use export::*;
pub use network::*;
pub use process::*;
pub use whois::*;

use tokio::task::spawn_blocking;
use std::net::IpAddr;
use crate::app_error::{AppError, AppResult};

async fn run_blocking_with_context<T, F>(context: &'static str, task: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    spawn_blocking(task)
        .await
        .map_err(|err| AppError::internal(format!("{context} 执行失败：{err}")))
}

fn to_tauri_error<T>(result: AppResult<T>) -> Result<T, String> {
    result.map_err(|err| err.to_string())
}

async fn run_blocking_to_tauri<T, F>(context: &'static str, task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    run_blocking_with_context(context, task).await.map_err(|err| err.to_string())
}

fn normalize_host(raw: &str, field: &'static str) -> AppResult<String> {
    let host = raw.trim();
    if host.is_empty() {
        return Err(AppError::validation(field, "不能为空"));
    }

    // 先允许直接解析 IP（包括 IPv4）
    if host.parse::<IpAddr>().is_ok() {
        return Ok(host.to_string());
    }

    if host.len() > 253 {
        return Err(AppError::validation(field, "长度不能超过 253 字符"));
    }

    if host
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    {
        return Err(AppError::validation(field, "格式不正确"));
    }

    if host.starts_with('-')
        || host.ends_with('-')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
    {
        return Err(AppError::validation(field, "格式不正确"));
    }

    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
    }) {
        return Err(AppError::validation(field, "格式不正确"));
    }

    Ok(host.to_lowercase())
}

fn normalize_subnet(raw: &str, field: &'static str) -> AppResult<String> {
    let subnet = raw.trim();
    if subnet.is_empty() {
        return Err(AppError::validation(field, "不能为空"));
    }

    let mut parts = subnet.split('/');
    let base = parts.next().ok_or_else(|| AppError::validation(field, "格式错误"))?;
    let mask = parts.next().ok_or_else(|| {
        AppError::validation(field, "需要 CIDR 格式，例如 192.168.1.0/24")
    })?;
    if parts.next().is_some() {
        return Err(AppError::validation(field, "只支持标准 CIDR 形式"));
    }

    let mask: u8 = mask
        .parse()
        .map_err(|_| AppError::validation(field, "掩码必须是 0-32 的数字"))?;
    if !(22..=24).contains(&mask) {
        return Err(AppError::validation(
            field,
            "当前支持 /22 ~ /24（最多 1022 个主机）",
        ));
    }

    let octets: Vec<&str> = base.split('.').collect();
    if octets.len() != 4 {
        return Err(AppError::validation(field, "基础地址格式应为 IPv4"));
    }
    for octet in octets {
        let n: u8 = octet
            .parse()
            .map_err(|_| AppError::validation(field, "包含无效 IPv4 段"))?;
        let _ = n;
    }

    Ok(subnet.to_string())
}

fn normalize_port(port: u16, field: &'static str) -> AppResult<u16> {
    if port == 0 {
        return Err(AppError::validation(field, "必须大于 0"));
    }
    Ok(port)
}

fn normalize_port_range(start: u16, end: u16) -> AppResult<(u16, u16)> {
    if start == 0 || end == 0 {
        return Err(AppError::validation("端口范围", "端口号必须大于 0"));
    }
    if start > end {
        return Err(AppError::validation("端口范围", "起始端口不能大于结束端口"));
    }
    Ok((start, end))
}

fn normalize_timeout_ms(timeout_ms: u64, field: &'static str) -> AppResult<u64> {
    if timeout_ms == 0 {
        return Err(AppError::validation(field, "不能为 0"));
    }
    if timeout_ms > 60_000 {
        return Err(AppError::validation(field, "不能超过 60000 毫秒"));
    }
    Ok(timeout_ms)
}

fn ensure_command_available(command: &str) -> AppResult<()> {
    command_exec::ensure_command_available(command)
}

/// Tauri 命令: 扫描端口
#[tauri::command]
async fn tauri_scan_ports(include_command: bool) -> Result<ScanResult, String> {
    run_blocking_to_tauri("端口扫描", move || core::scan_ports(include_command)).await
}

/// Tauri 命令: 按应用分组
#[tauri::command]
async fn tauri_scan_ports_grouped() -> Result<Vec<AppGroup>, String> {
    run_blocking_to_tauri("应用分组扫描", move || core::scan_ports_grouped()).await
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
async fn tauri_discover_devices(subnet: String) -> Result<Vec<network::NetworkDevice>, String> {
    let subnet = to_tauri_error(normalize_subnet(&subnet, "子网"))?;
    run_blocking_to_tauri("局域网设备发现", move || network::discover_devices(&subnet)).await
}

/// Tauri 命令: 智能扫描（异步）
#[tauri::command]
async fn tauri_smart_scan(subnet: String) -> Result<advanced_scan::AdvancedScanResult, String> {
    let subnet = to_tauri_error(normalize_subnet(&subnet, "子网"))?;
    run_blocking_to_tauri("高级网段扫描", move || advanced_scan::smart_scan(&subnet)).await
}

/// Tauri 命令: 检查是否有高级扫描权限
#[tauri::command]
fn tauri_check_permission() -> bool {
    advanced_scan::check_raw_socket_permission()
}

/// Tauri 命令: 快速端口扫描（异步）
#[tauri::command]
async fn tauri_quick_scan(ip: String) -> Result<Vec<network::RemotePort>, String> {
    let ip = to_tauri_error(normalize_host(&ip, "目标地址"))?;
    run_blocking_to_tauri("常用端口扫描", move || network::quick_scan(&ip)).await
}

/// Tauri 命令: 自定义端口扫描（异步）
#[tauri::command]
async fn tauri_scan_ports_range(
    ip: String,
    start: u16,
    end: u16,
    timeout_ms: u64,
) -> Result<Vec<network::RemotePort>, String> {
    let ip = to_tauri_error(normalize_host(&ip, "目标地址"))?;
    let (start, end) = to_tauri_error(normalize_port_range(start, end))?;
    let timeout_ms = to_tauri_error(normalize_timeout_ms(timeout_ms, "扫描超时"))?;
    run_blocking_to_tauri(
        "自定义端口扫描",
        move || network::full_scan(&ip, start, end, timeout_ms),
    )
    .await
}

/// Tauri 命令: 获取常用端口列表
#[tauri::command]
fn tauri_get_common_ports() -> Vec<u16> {
    network::get_common_ports()
}

/// Tauri 命令: Ping 测试（异步）
#[tauri::command]
async fn tauri_ping(ip: String, count: u32) -> Result<network::PingResult, String> {
    let ip = to_tauri_error(normalize_host(&ip, "Ping 目标"))?;
    to_tauri_error(ensure_command_available("ping"))?;
    if count == 0 || count > 100 {
        return Err(AppError::validation("Ping 次数", "应在 1-100 之间").to_string());
    }
    run_blocking_to_tauri("Ping 测试", move || network::ping_test(&ip, count)).await
}

/// Tauri 命令: 单次 Ping（异步，用于流式显示）
#[tauri::command]
async fn tauri_ping_one(ip: String, seq: u32) -> Result<network::PingOneResult, String> {
    let ip = to_tauri_error(normalize_host(&ip, "Ping 目标"))?;
    to_tauri_error(ensure_command_available("ping"))?;
    run_blocking_to_tauri("单次 Ping", move || network::ping_one(&ip, seq)).await
}

/// Tauri 命令: Traceroute（异步）
#[tauri::command]
async fn tauri_traceroute(ip: String) -> Result<network::TracerouteResult, String> {
    let ip = to_tauri_error(normalize_host(&ip, "Traceroute 目标"))?;
    to_tauri_error(ensure_command_available("traceroute").or_else(|_| ensure_command_available("tracert")))?;
    run_blocking_to_tauri("Traceroute", move || network::traceroute(&ip)).await
}

/// Tauri 命令: 探测服务类型（异步）
#[tauri::command]
async fn tauri_detect_service(ip: String, port: u16) -> Result<network::ServiceInfo, String> {
    let ip = to_tauri_error(normalize_host(&ip, "目标地址"))?;
    let port = to_tauri_error(normalize_port(port, "服务检测端口"))?;
    run_blocking_to_tauri("服务探测", move || network::detect_service_type(&ip, port)).await
}

/// Tauri 命令: 批量探测服务（异步）
#[tauri::command]
async fn tauri_detect_services(ip: String, ports: Vec<u16>) -> Result<Vec<network::ServiceInfo>, String> {
    let ip = to_tauri_error(normalize_host(&ip, "目标地址"))?;
    let mut ports: Vec<u16> = ports
        .into_iter()
        .filter_map(|port| (1..=65535).contains(&port).then_some(port))
        .collect();
    if ports.is_empty() {
        return Ok(vec![]);
    }
    ports.sort_unstable();
    ports.dedup();
    run_blocking_to_tauri("批量服务探测", move || network::detect_services(&ip, &ports)).await
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
    let target = to_tauri_error(normalize_host(&target, "目标地址"))?;
    network::resolve_target(&target)
}

// ===== 进程管理命令 =====

/// Tauri 命令: 终止进程
#[tauri::command]
fn tauri_kill_process(pid: u32, force: bool) -> process::KillResult {
    if pid == 0 {
        return process::KillResult {
            success: false,
            pid,
            message: "进程 ID 不能为 0".to_string(),
        };
    }
    process::kill_process(pid, force)
}

/// Tauri 命令: 终止占用端口的进程
#[tauri::command]
fn tauri_kill_port(port: u16) -> process::KillResult {
    let port = match normalize_port(port, "端口") {
        Ok(v) => v,
        Err(e) => {
            return process::KillResult {
                success: false,
                pid: 0,
                message: e.to_string(),
            }
        }
    };
    process::kill_port_process(port)
}

/// Tauri 命令: 获取进程信息
#[tauri::command]
fn tauri_get_process_info(pid: u32) -> Option<process::ProcessInfo> {
    process::get_process_info(pid)
}

// ===== 导出命令 =====

/// Tauri 命令: 导出到 CSV
#[tauri::command]
fn tauri_export_csv(ports: Vec<core::PortInfo>, path: String) -> export::ExportResult {
    export::export_to_csv(&ports, &path)
}

/// Tauri 命令: 导出到 JSON
#[tauri::command]
fn tauri_export_json(scan_result: core::ScanResult, path: String) -> export::ExportResult {
    export::export_to_json(&scan_result, &path)
}

/// Tauri 命令: 导出到文本
#[tauri::command]
fn tauri_export_txt(ports: Vec<core::PortInfo>, path: String) -> export::ExportResult {
    export::export_to_txt(&ports, &path)
}

/// Tauri 命令: 自动导出（使用默认路径）
#[tauri::command]
fn tauri_export_auto(
    ports: Vec<core::PortInfo>,
    scan_result: core::ScanResult,
    format: String,
) -> export::ExportResult {
    let export_format = match format.to_lowercase().as_str() {
        "csv" => export::ExportFormat::Csv,
        "json" => export::ExportFormat::Json,
        "txt" => export::ExportFormat::Txt,
        _ => export::ExportFormat::Csv,
    };
    export::export_auto(&ports, &scan_result, export_format)
}

/// Tauri 命令: 获取默认导出目录
#[tauri::command]
fn tauri_get_export_dir() -> String {
    export::get_default_export_dir()
        .to_string_lossy()
        .to_string()
}

/// Tauri 命令: 获取扫描历史摘要
#[tauri::command]
fn tauri_get_history_summary() -> Vec<export::HistorySummary> {
    export::get_history_summary()
}

/// Tauri 命令: 保存扫描到历史
#[tauri::command]
fn tauri_save_to_history(scan_result: core::ScanResult) -> Result<(), String> {
    export::save_to_history(&scan_result)
}

// ===== DNS 查询命令 =====

/// Tauri 命令: DNS 查询
#[tauri::command]
async fn tauri_dns_query(
    domain: String,
    record_type: String,
    dns_server: Option<String>,
) -> Result<dns::DnsQueryResult, String> {
    let domain = to_tauri_error(normalize_host(&domain, "域名"))?;
    let dns_server = dns_server
        .map(|s| to_tauri_error(normalize_host(&s, "DNS服务器")))
        .transpose()?;
    run_blocking_to_tauri("DNS 查询", move || dns::dns_query(domain, record_type, dns_server)).await
}

/// Tauri 命令: 获取常用 DNS 服务器列表
#[tauri::command]
fn tauri_get_dns_servers() -> Vec<dns::DnsServerInfo> {
    dns::get_popular_dns_servers()
}

/// Tauri 命令: 批量 DNS 查询
#[tauri::command]
async fn tauri_dns_batch_query(
    domain: String,
    record_types: Vec<String>,
    dns_server: Option<String>,
) -> Result<Vec<dns::DnsQueryResult>, String> {
    let domain = to_tauri_error(normalize_host(&domain, "域名"))?;
    let dns_server = dns_server
        .map(|s| to_tauri_error(normalize_host(&s, "DNS服务器")))
        .transpose()?;
    run_blocking_to_tauri("批量 DNS 查询", move || dns::batch_query(domain, record_types, dns_server)).await
}

// ===== Whois 查询命令 =====

/// Tauri 命令: Whois 域名查询
#[tauri::command]
async fn tauri_whois_query(domain: String) -> Result<whois::WhoisResult, String> {
    let domain = to_tauri_error(normalize_host(&domain, "域名"))?;
    run_blocking_to_tauri("Whois 查询", move || whois::whois_query(domain)).await
}

// ===== SSL 证书检查命令 =====

/// Tauri 命令: 检查 SSL 证书
#[tauri::command]
async fn tauri_check_ssl_cert(host: String, port: Option<u16>) -> Result<ssl::SslCertInfo, String> {
    let host = to_tauri_error(normalize_host(&host, "主机"))?;
    let port = port.map(|p| to_tauri_error(normalize_port(p, "端口"))).transpose()?;
    to_tauri_error(ensure_command_available("openssl"))?;
    run_blocking_to_tauri("SSL 证书检查", move || ssl::check_ssl_cert(host, port)).await
}

/// Tauri 命令: 批量检查 SSL 证书
#[tauri::command]
async fn tauri_check_ssl_certs(targets: Vec<(String, Option<u16>)>) -> Result<Vec<ssl::SslCertInfo>, String> {
    let targets: Vec<(String, Option<u16>)> = to_tauri_error(
        targets
        .into_iter()
        .map(|(host, port)| {
            Ok((
                normalize_host(&host, "主机")?,
                port.map(|p| normalize_port(p, "端口")).transpose()?,
            ))
        })
        .collect::<AppResult<Vec<_>>>(),
    )?;
    to_tauri_error(ensure_command_available("openssl"))?;
    run_blocking_to_tauri("批量 SSL 证书检查", move || ssl::check_ssl_certs(targets)).await
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
            tauri_resolve_target,
            // 进程管理
            tauri_kill_process,
            tauri_kill_port,
            tauri_get_process_info,
            // 导出
            tauri_export_csv,
            tauri_export_json,
            tauri_export_txt,
            tauri_export_auto,
            tauri_get_export_dir,
            tauri_get_history_summary,
            tauri_save_to_history,
            // DNS 查询
            tauri_dns_query,
            tauri_get_dns_servers,
            tauri_dns_batch_query,
            // Whois
            tauri_whois_query,
            // SSL 证书检查
            tauri_check_ssl_cert,
            tauri_check_ssl_certs
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_normalize_host_accepts_ip() {
        let host = normalize_host(" 127.0.0.1 ", "目标地址").unwrap();
        assert_eq!(host, "127.0.0.1");
    }

    #[test]
    fn test_normalize_host_rejects_empty() {
        let err = normalize_host("   ", "目标地址").unwrap_err();
        assert!(matches!(err, AppError::Validation { field: "目标地址", .. }));
        assert_eq!(err.to_string(), "目标地址 校验失败：不能为空");
    }

    #[test]
    fn test_normalize_host_rejects_invalid_char() {
        let err = normalize_host("bad_host!", "目标地址").unwrap_err();
        assert_eq!(err.to_string(), "目标地址 校验失败：格式不正确");
    }

    #[test]
    fn test_normalize_host_lowercase() {
        let host = normalize_host("EXAMPLE.COM", "目标地址").unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn test_normalize_subnet_invalid_format() {
        let err = normalize_subnet("192.168.1.1", "子网").unwrap_err();
        assert_eq!(err.to_string(), "子网 校验失败：需要 CIDR 格式，例如 192.168.1.0/24");
    }

    #[test]
    fn test_normalize_subnet_supports_23() {
        let subnet = normalize_subnet("192.168.1.0/23", "子网").unwrap();
        assert_eq!(subnet, "192.168.1.0/23");
    }

    #[test]
    fn test_normalize_subnet_supports_24() {
        let subnet = normalize_subnet("10.0.0.0/24", "子网").unwrap();
        assert_eq!(subnet, "10.0.0.0/24");
    }

    #[test]
    fn test_normalize_subnet_rejects_oversize() {
        let err = normalize_subnet("192.168.0.0/21", "子网").unwrap_err();
        assert_eq!(err.to_string(), "子网 校验失败：当前支持 /22 ~ /24（最多 1022 个主机）");
    }

    #[test]
    fn test_normalize_port_range_reject_start_gt_end() {
        let err = normalize_port_range(2000, 1000).unwrap_err();
        assert_eq!(err.to_string(), "端口范围 校验失败：起始端口不能大于结束端口");
    }

    #[test]
    fn test_normalize_timeout_too_high() {
        let err = normalize_timeout_ms(61000, "扫描超时").unwrap_err();
        assert_eq!(err.to_string(), "扫描超时 校验失败：不能超过 60000 毫秒");
    }

    #[test]
    fn test_to_tauri_error_is_string() {
        let err = to_tauri_error(normalize_port_range(0, 0)).unwrap_err();
        assert_eq!(err, "端口范围 校验失败：端口号必须大于 0");
    }

    #[test]
    fn test_ensure_command_available_not_found() {
        let err = to_tauri_error(ensure_command_available("a_command_that_not_exists_12345")).unwrap_err();
        assert!(err.contains("不可用"));
    }

    #[test]
    fn test_to_tauri_error_command_available_current_binary() {
        let exe = env::current_exe().unwrap();
        let exe = exe.to_string_lossy();
        let err = to_tauri_error(ensure_command_available(&exe));
        assert!(err.is_ok());
    }

    #[test]
    fn test_tauri_dns_query_rejects_empty_domain() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_dns_query(" ".to_string(), "A".to_string(), None))
            .unwrap_err();
        assert_eq!(err, "域名 校验失败：不能为空");
    }

    #[test]
    fn test_tauri_whois_query_rejects_empty_domain() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_whois_query(" ".to_string()))
            .unwrap_err();
        assert_eq!(err, "域名 校验失败：不能为空");
    }

    #[test]
    fn test_tauri_scan_ports_range_reject_invalid_range() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_scan_ports_range(
                "127.0.0.1".to_string(),
                2000,
                1000,
                3000,
            ))
            .unwrap_err();
        assert_eq!(err, "端口范围 校验失败：起始端口不能大于结束端口");
    }

    #[test]
    fn test_tauri_ping_rejects_invalid_count() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_ping("127.0.0.1".to_string(), 0))
            .unwrap_err();
        assert_eq!(err, "Ping 次数 校验失败：应在 1-100 之间");
    }

    #[test]
    fn test_tauri_check_ssl_cert_invalid_port() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_check_ssl_cert("127.0.0.1".to_string(), Some(0)))
            .unwrap_err();
        assert_eq!(err, "端口 校验失败：必须大于 0");
    }

    #[test]
    fn test_tauri_dns_batch_query_rejects_invalid_dns_server() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_dns_batch_query(
                "example.com".to_string(),
                vec!["A".to_string()],
                Some("bad host!".to_string()),
            ))
            .unwrap_err();
        assert_eq!(err, "DNS服务器 校验失败：格式不正确");
    }

    #[test]
    fn test_tauri_check_ssl_certs_rejects_invalid_target() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_check_ssl_certs(vec![
                ("".to_string(), Some(443)),
                ("example.com".to_string(), Some(0)),
            ]))
            .unwrap_err();
        assert_eq!(err, "主机 校验失败：不能为空");
    }

    #[test]
    fn test_tauri_discover_devices_rejects_invalid_subnet() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_discover_devices("10.0.0.1".to_string()))
            .unwrap_err();
        assert_eq!(err, "子网 校验失败：需要 CIDR 格式，例如 192.168.1.0/24");
    }

    #[test]
    fn test_tauri_detect_services_accepts_empty_ports() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt
            .block_on(tauri_detect_services("127.0.0.1".to_string(), vec![]))
            .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_tauri_detect_services_rejects_invalid_host() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_detect_services("bad host!".to_string(), vec![80, 443]))
            .unwrap_err();
        assert_eq!(err, "目标地址 校验失败：格式不正确");
    }

    #[test]
    fn test_tauri_smart_scan_rejects_invalid_subnet() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_smart_scan("10.0.0.1".to_string()))
            .unwrap_err();
        assert_eq!(err, "子网 校验失败：需要 CIDR 格式，例如 192.168.1.0/24");
    }

    #[test]
    fn test_tauri_traceroute_rejects_empty_target() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_traceroute(" ".to_string()))
            .unwrap_err();
        assert_eq!(err, "Traceroute 目标 校验失败：不能为空");
    }

    #[test]
    fn test_tauri_ping_rejects_invalid_target() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_ping(" bad host ".to_string(), 1))
            .unwrap_err();
        assert_eq!(err, "Ping 目标 校验失败：格式不正确");
    }

    #[test]
    fn test_tauri_ping_one_rejects_invalid_target() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_ping_one("".to_string(), 1))
            .unwrap_err();
        assert_eq!(err, "Ping 目标 校验失败：不能为空");
    }

    #[test]
    fn test_tauri_detect_service_rejects_invalid_port() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_detect_service("127.0.0.1".to_string(), 0))
            .unwrap_err();
        assert_eq!(err, "服务检测端口 校验失败：必须大于 0");
    }

    #[test]
    fn test_tauri_check_ssl_certs_rejects_invalid_port() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_check_ssl_certs(vec![("example.com".to_string(), Some(0))]))
            .unwrap_err();
        assert_eq!(err, "端口 校验失败：必须大于 0");
    }

    #[test]
    fn test_tauri_check_ssl_certs_accepts_empty_targets() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(tauri_check_ssl_certs(vec![])).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_tauri_quick_scan_rejects_invalid_host() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_quick_scan("..bad".to_string()))
            .unwrap_err();
        assert_eq!(err, "目标地址 校验失败：格式不正确");
    }

    #[test]
    fn test_tauri_scan_ports_range_rejects_zero_timeout() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_scan_ports_range(
                "127.0.0.1".to_string(),
                80,
                81,
                0,
            ))
            .unwrap_err();
        assert_eq!(err, "扫描超时 校验失败：不能为 0");
    }

    #[test]
    fn test_tauri_dns_query_rejects_invalid_dns_server() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(tauri_dns_query(
                "example.com".to_string(),
                "A".to_string(),
                Some("bad host".to_string()),
            ))
            .unwrap_err();
        assert_eq!(err, "DNS服务器 校验失败：格式不正确");
    }

    #[test]
    fn test_tauri_dns_batch_query_accepts_empty_record_types() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt
            .block_on(tauri_dns_batch_query(
                "example.com".to_string(),
                vec![],
                None,
            ))
            .unwrap();
        assert!(result.is_empty());
    }
}
