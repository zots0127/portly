//! Export module for Portly
//! Provides data export functionality in multiple formats (CSV, JSON)

use serde::{Deserialize, Serialize};
use chrono::Local;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use crate::core::{PortInfo, ScanResult};

/// Export format options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Json,
    Txt,
}

/// Export result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    pub success: bool,
    pub path: Option<String>,
    pub message: String,
    pub record_count: usize,
}

/// Scan history entry for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    pub timestamp: String,
    pub port_count: usize,
    pub scan_duration_ms: u64,
    pub ports: Vec<PortInfo>,
}

/// Export port data to CSV format
pub fn export_to_csv(ports: &[PortInfo], path: &str) -> ExportResult {
    let mut csv_content = String::new();
    
    // Header
    csv_content.push_str("Port,Protocol,Address,PID,Process,User,Command\n");
    
    // Data rows
    for port in ports {
        let command = port.command.as_deref().unwrap_or("");
        // Escape commas and quotes in command
        let escaped_command = if command.contains(',') || command.contains('"') {
            format!("\"{}\"", command.replace('"', "\"\""))
        } else {
            command.to_string()
        };
        
        csv_content.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            port.port,
            port.protocol,
            port.address,
            port.pid,
            port.process,
            port.user,
            escaped_command
        ));
    }
    
    match write_file(path, &csv_content) {
        Ok(_) => ExportResult {
            success: true,
            path: Some(path.to_string()),
            message: format!("成功导出 {} 条记录到 CSV", ports.len()),
            record_count: ports.len(),
        },
        Err(e) => ExportResult {
            success: false,
            path: None,
            message: format!("CSV 导出失败: {}", e),
            record_count: 0,
        },
    }
}

/// Export port data to JSON format
pub fn export_to_json(scan_result: &ScanResult, path: &str) -> ExportResult {
    let export_data = serde_json::json!({
        "export_time": Local::now().to_rfc3339(),
        "scan_time": scan_result.scan_time,
        "total_ports": scan_result.total_ports,
        "ports": scan_result.ports,
    });
    
    match serde_json::to_string_pretty(&export_data) {
        Ok(json_str) => {
            match write_file(path, &json_str) {
                Ok(_) => ExportResult {
                    success: true,
                    path: Some(path.to_string()),
                    message: format!("成功导出 {} 条记录到 JSON", scan_result.total_ports),
                    record_count: scan_result.total_ports,
                },
                Err(e) => ExportResult {
                    success: false,
                    path: None,
                    message: format!("JSON 写入失败: {}", e),
                    record_count: 0,
                },
            }
        }
        Err(e) => ExportResult {
            success: false,
            path: None,
            message: format!("JSON 序列化失败: {}", e),
            record_count: 0,
        },
    }
}

/// Export port data to plain text format (human-readable)
pub fn export_to_txt(ports: &[PortInfo], path: &str) -> ExportResult {
    let mut txt_content = String::new();
    
    // Header with timestamp
    txt_content.push_str(&format!(
        "Portly 端口扫描报告\n导出时间: {}\n",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    ));
    txt_content.push_str(&format!("共计 {} 个端口\n", ports.len()));
    txt_content.push_str("=".repeat(80).as_str());
    txt_content.push('\n');
    txt_content.push('\n');
    
    // Port entries
    for port in ports {
        txt_content.push_str(&format!(
            "端口: {:<6} | {} | {} | PID: {}\n",
            port.port,
            port.protocol,
            port.process,
            port.pid
        ));
        txt_content.push_str(&format!("  地址: {} | 用户: {}\n", port.address, port.user));
        if let Some(cmd) = &port.command {
            txt_content.push_str(&format!("  命令: {}\n", cmd));
        }
        txt_content.push('\n');
    }
    
    match write_file(path, &txt_content) {
        Ok(_) => ExportResult {
            success: true,
            path: Some(path.to_string()),
            message: format!("成功导出 {} 条记录到文本文件", ports.len()),
            record_count: ports.len(),
        },
        Err(e) => ExportResult {
            success: false,
            path: None,
            message: format!("文本导出失败: {}", e),
            record_count: 0,
        },
    }
}

/// Get default export directory (user's Downloads folder)
pub fn get_default_export_dir() -> PathBuf {
    dirs::download_dir()
        .or_else(dirs::document_dir)
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Generate default export filename with timestamp
pub fn generate_export_filename(format: &ExportFormat) -> String {
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let extension = match format {
        ExportFormat::Csv => "csv",
        ExportFormat::Json => "json",
        ExportFormat::Txt => "txt",
    };
    format!("portly_export_{}.{}", timestamp, extension)
}

/// Helper function to write content to file
fn write_file(path: &str, content: &str) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

/// Export ports with auto-generated filename
pub fn export_auto(ports: &[PortInfo], scan_result: &ScanResult, format: ExportFormat) -> ExportResult {
    let dir = get_default_export_dir();
    let filename = generate_export_filename(&format);
    let full_path = dir.join(&filename);
    let path_str = full_path.to_string_lossy().to_string();
    
    match format {
        ExportFormat::Csv => export_to_csv(ports, &path_str),
        ExportFormat::Json => export_to_json(scan_result, &path_str),
        ExportFormat::Txt => export_to_txt(ports, &path_str),
    }
}

// ===== Scan History Persistence =====

/// Get the path to the history file
fn get_history_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("portly")
        .join("scan_history.json")
}

/// Load scan history from file
pub fn load_scan_history() -> Vec<ScanHistoryEntry> {
    let path = get_history_path();
    if !path.exists() {
        return Vec::new();
    }
    
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            serde_json::from_str(&content).unwrap_or_default()
        }
        Err(_) => Vec::new(),
    }
}

/// Save a scan to history
pub fn save_to_history(scan_result: &ScanResult) -> Result<(), String> {
    let path = get_history_path();
    
    // Ensure directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("创建历史目录失败: {}", e))?;
    }
    
    // Load existing history
    let mut history = load_scan_history();
    
    // Add new entry
    let entry = ScanHistoryEntry {
        timestamp: Local::now().to_rfc3339(),
        port_count: scan_result.total_ports,
        scan_duration_ms: 0, // Duration not tracked in current ScanResult
        ports: scan_result.ports.clone(),
    };
    
    history.push(entry);
    
    // Keep only last 100 entries
    if history.len() > 100 {
        history = history.split_off(history.len() - 100);
    }
    
    // Save to file
    let json = serde_json::to_string_pretty(&history)
        .map_err(|e| format!("序列化历史数据失败: {}", e))?;
    
    std::fs::write(&path, json)
        .map_err(|e| format!("写入历史文件失败: {}", e))?;
    
    Ok(())
}

/// Get scan history summary (without full port data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySummary {
    pub timestamp: String,
    pub port_count: usize,
    pub scan_duration_ms: u64,
}

pub fn get_history_summary() -> Vec<HistorySummary> {
    load_scan_history()
        .into_iter()
        .map(|entry| HistorySummary {
            timestamp: entry.timestamp,
            port_count: entry.port_count,
            scan_duration_ms: entry.scan_duration_ms,
        })
        .collect()
}
