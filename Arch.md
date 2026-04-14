# Arch（完整项目数据流与模块图谱）

## 0. 范围与事实基线

本图谱基于以下代码真实调用链整理：

- 前端入口：`src/main.ts`
- 前端状态与反馈：`src/network-utils.ts`、`src/scan-ui-state.ts`、`src/error-utils.ts`、`src/ui-feedback.ts`
- Tauri 命令入口：`src-tauri/src/lib.rs`
- 后端模块：`src-tauri/src/{core,network,advanced_scan,dns,whois,ssl,process,docker,export,command_exec,app_error}.rs`
- CLI 入口：`src-tauri/src/bin/cli.rs`
- 持久化：`src-tauri/src/export.rs`（`scan_history.json`）

> 结论先行：当前项目没有关系型数据库/嵌入式数据库（如 SQLite）。
> “历史数据存储”是 **本地 JSON 文件持久化**（`scan_history.json`）。

---

## 1. 全局端到端数据流（GUI + CLI）

```mermaid
flowchart LR
    U["User"] --> GUI["Frontend UI src main ts"]
    U --> CLI["CLI portly cli"]

    GUI --> INVOKE["tauri invoke api"]
    INVOKE --> TAURI["Tauri commands lib rs"]

    CLI --> CORECLI["core scan ports and grouped scan"]

    TAURI --> CORE["core rs"]
    TAURI --> NET["network rs"]
    TAURI --> ADV["advanced scan rs"]
    TAURI --> DNS["dns rs"]
    TAURI --> WHOIS["whois rs"]
    TAURI --> SSL["ssl rs"]
    TAURI --> PROC["process rs"]
    TAURI --> DOCKER["docker rs"]
    TAURI --> EXP["export rs"]

    CORE --> CMD["command exec rs"]
    NET --> CMD
    DNS --> CMD
    SSL --> CMD
    PROC --> CMD
    DOCKER --> CMD

    CMD --> OSCMD["OS commands lsof ss netstat ping traceroute dig openssl docker"]
    NET --> SOCK["Socket TCP connect"]
    WHOIS --> TCP43["Whois TCP 43"]

    EXP --> FS1["Export files in Downloads"]
    EXP --> FS2["History file scan history json"]

    TAURI --> ERR["app error rs"]
    ERR --> GUI
    GUI --> TOAST["UI feedback showToast"]

    CORECLI --> OUT["Terminal output and JSON"]
```

---

## 2. 前端页面级数据流（多视角）

### 2.1 页面与命令路由视角

```mermaid
flowchart TD
    subgraph LocalPage[Local Page]
        L1[scanPorts] --> C1[tauri_scan_ports]
        L1 --> C2[tauri_get_docker_containers]
        L2[scanGrouped] --> C3[tauri_scan_ports_grouped]
        L3[kill process button] --> C4[tauri_kill_process]
        L4[exportData] --> C5[tauri_export_auto]
    end

    subgraph NetworkPage[Network Page]
        N1[loadInterfaces] --> C6[tauri_get_interfaces]
        N1 --> C7[tauri_get_current_subnet]
        N2[discoverDevices] --> C8[tauri_discover_devices]
        N3[scanRemotePorts] --> C9[tauri_quick_scan]
        N3 --> C10[tauri_scan_ports_range]
        N4[manual target resolve] --> C11[tauri_resolve_target]
        N5[single ping] --> C12[tauri_ping_one]
        N6[traceroute] --> C13[tauri_traceroute]
        N7[multi ping] --> C12
    end

    subgraph MonitorPage[Monitor Page]
        M1[startMonitor] --> C8
        M1 --> C12
        M2[render canvas/grid stats] --> UI1[DOM + Canvas]
    end

    subgraph DnsWhoisSsl[DNS / WHOIS / SSL]
        D1[queryDns] --> C14[tauri_dns_query]
        W1[queryWhois] --> C15[tauri_whois_query]
        S1[checkSslCert] --> C16[tauri_check_ssl_cert]
    end

    C1 --> RENDER[Render DOM]
    C2 --> RENDER
    C3 --> RENDER
    C4 --> RENDER
    C5 --> RENDER
    C6 --> RENDER
    C7 --> RENDER
    C8 --> RENDER
    C9 --> RENDER
    C10 --> RENDER
    C11 --> RENDER
    C12 --> RENDER
    C13 --> RENDER
    C14 --> RENDER
    C15 --> RENDER
    C16 --> RENDER
```

### 2.2 前端状态机视角（扫描/监测）

```mermaid
stateDiagram-v2
    [*] --> Idle

    Idle --> LoadingDevices: discoverDevices/startMonitor
    LoadingDevices --> DeviceReady: tauri_discover_devices success
    LoadingDevices --> Error: tauri_discover_devices fail

    DeviceReady --> PortScanning: tauri_quick_scan / tauri_scan_ports_range
    PortScanning --> DeviceReady: renderPortResults
    PortScanning --> Error: scan error

    DeviceReady --> PingLoop: tauri_ping_one interval
    PingLoop --> DeviceReady: stopPing
    PingLoop --> Error: ping invoke error

    DeviceReady --> TraceRunning: tauri_traceroute
    TraceRunning --> DeviceReady
    TraceRunning --> Error

    Error --> Idle: reset / retry
```

### 2.3 前端错误流视角

```mermaid
flowchart LR
    INVOKEERR["invoke error or result error"] --> EUTIL["error utils parse and format"]
    EUTIL --> REPORT["report command error"]
    REPORT --> TOAST["show toast"]
    REPORT --> CONSOLE["console error"]
```

---

## 3. Tauri 命令分发总图（lib.rs）

```mermaid
flowchart LR
    IN[invoke tauri_*] --> V[normalize_host/subnet/port/timeout]
    V --> B[run_blocking_to_tauri or direct fn]

    B --> M1[core]
    B --> M2[network]
    B --> M3[advanced_scan]
    B --> M4[docker]
    B --> M5[process]
    B --> M6[export]
    B --> M7[dns]
    B --> M8[whois]
    B --> M9[ssl]

    B --> SB[spawn_blocking]
    SB --> RES[AppResult<T>]
    RES --> MAP[to_string error mapping]
    MAP --> OUT[Result<T, String> to frontend]
```

---

## 4. 后端通用执行与错误治理数据流

```mermaid
flowchart TD
    CMDENTRY[tauri command] --> VALIDATE[normalize_*]
    VALIDATE --> BLOCK[run_blocking_with_context]
    BLOCK --> POOL[tokio spawn_blocking]
    POOL --> BIZ[module function]

    BIZ --> EXEC1[command_exec::run_command]
    BIZ --> EXEC2[run_command_required]
    BIZ --> EXEC3[run_command_with_timeout]
    BIZ --> IO1[socket/tcp read write]
    BIZ --> IO2[file read/write]

    EXEC1 --> APPERR[AppError enum]
    EXEC2 --> APPERR
    EXEC3 --> APPERR
    IO1 --> APPERR
    IO2 --> APPERR

    APPERR --> DISP[Display::fmt]
    DISP --> TAURIERR[String error]
    TAURIERR --> FRONTEND[reportCommandError + toast]
```

---

## 5. 模块级数据流图（逐模块）

### 5.1 `core.rs`（本机端口扫描）

```mermaid
flowchart LR
    A[get_listening_ports_raw] --> B{OS}
    B -->|macOS| C[lsof -i -P -n]
    B -->|Linux| D[ss -tlnp fallback lsof]
    B -->|Windows| E[netstat -ano]

    C --> P1[parse_lsof_output]
    D --> P2[parse_ss_output/parse_lsof_output]
    E --> P3[parse_netstat_windows]

    P1 --> PORTS[Vec<PortInfo>]
    P2 --> PORTS
    P3 --> PORTS

    PORTS --> SCAN[scan_ports]
    SCAN --> CMDOPT{include_command?}
    CMDOPT -->|yes| PCMD[get_process_command by PID]
    CMDOPT -->|no| SUM
    PCMD --> SUM[ScanResult]

    PORTS --> GROUP[scan_ports_grouped]
    GROUP --> APPG[Vec<AppGroup>]

    PORTS --> FILTER[filter_ports]
```

### 5.2 `network.rs`（网段发现 + 远程扫描 + 连通性）

```mermaid
flowchart TD
    S0[input subnet] --> S1[subnet_host_addresses /22~24]
    S1 --> S2[get_arp_table]
    S1 --> S3[ping_sweep multithread]
    S2 --> S4[merge device_map]
    S3 --> S4
    S4 --> S5[online filter + resolve_hostname]
    S5 --> DEV[Vec<NetworkDevice>]

    IP1[input ip + ports] --> P1[scan_ports_sync or async]
    P1 --> P2[Tcp connect timeout]
    P2 --> RP[Vec<RemotePort>]

    R1[resolve_target] --> R2{is IP?}
    R2 -->|yes| R3[return ip + reverse hostname]
    R2 -->|no| R4[ToSocketAddrs DNS]
    R4 --> R5[ResolveResult]

    T1[ping_test/ping_one] --> T2[run ping command]
    T2 --> T3[parse loss/latency/ttl]

    T4[traceroute] --> T5[run traceroute/tracert]
    T5 --> T6[parse hops]

    SV1[detect_service_type] --> SV2{HTTP-like port?}
    SV2 -->|yes| SV3[probe_http_service]
    SV2 -->|no| SV4[infer by port]
```

### 5.3 `advanced_scan.rs`（高级扫描策略）

```mermaid
flowchart LR
    A[subnet] --> B{platform arp_scan_advanced}
    B -->|success| C[ARP raw socket result]
    B -->|fail| D[network::discover_devices fallback]

    C --> E[AdvancedScanResult method=ARP高级 has_permission=true]
    D --> F[AdvancedScanResult method=Ping/ARP基础 has_permission=false]
```

### 5.4 `dns.rs`（多记录 DNS 查询）

```mermaid
flowchart TD
    Q1[dns_query domain + type + dns_server] --> Q2[RecordType::parse]
    Q2 --> Q3{platform}

    Q3 -->|Unix| U1[query_via_dig]
    Q3 -->|Windows| W1[query_via_nslookup]

    U1 --> U2[parse_dig_output]
    W1 --> W2[parse_nslookup_output]

    U1 --> F1{dig unavailable or empty?}
    W1 --> F2{nslookup unavailable or empty?}
    F1 --> SYS[query_via_system_resolver A/AAAA]
    F2 --> SYS

    U2 --> R[DnsQueryResult]
    W2 --> R
    SYS --> R
```

### 5.5 `whois.rs`（Whois 数据流）

```mermaid
flowchart LR
    A[whois_query domain] --> B[find_whois_server by TLD]
    B --> C[TcpStream connect server:43]
    C --> D[write domain + read response]
    D --> E[parse_whois_output]
    E --> F[WhoisResult fields]
```

### 5.6 `ssl.rs`（SSL 证书检测）

```mermaid
flowchart TD
    A[check_ssl_cert host port] --> B[run openssl s_client -showcerts]
    B --> C{has cert block?}
    C -->|no| E1[SslCertInfo error]
    C -->|yes| D[parse_openssl_output]

    D --> D1[subject issuer serial version]
    D --> D2[notBefore notAfter -> days_until_expiry]
    D --> D3[parse_cert_chain]
    D --> D4[extract tls_version cipher key_size]
    D1 --> OUT[SslCertInfo]
    D2 --> OUT
    D3 --> OUT
    D4 --> OUT
```

### 5.7 `process.rs`（进程终止）

```mermaid
flowchart LR
    A[kill_process pid force] --> B[get_process_info]
    B --> C{protected process?}
    C -->|yes and not force| D[deny with message]
    C -->|no| E[run kill or taskkill]
    E --> F[KillResult]

    G[kill_port_process port] --> H[lsof -ti :port / netstat -ano]
    H --> I[collect PIDs]
    I --> J[loop kill_process]
    J --> K[merged KillResult]
```

### 5.8 `docker.rs`（容器端口映射）

```mermaid
flowchart LR
    A[get_docker_containers] --> B[docker ps --format]
    B --> C[parse_docker_ports]
    C --> D[Vec<DockerContainer>]

    D --> E[get_port_to_container_map]
    D --> F[get_docker_port_info]
```

### 5.9 `export.rs`（导出与历史）

```mermaid
flowchart TD
    A[export_auto ports scanResult format] --> B{format}
    B --> C1[export_to_csv]
    B --> C2[export_to_json]
    B --> C3[export_to_txt]
    C1 --> W[write_file]
    C2 --> W
    C3 --> W
    W --> FS[Downloads/*]

    H1[save_to_history scan_result] --> H2[get_history_path data_local_dir/portly/scan_history.json]
    H2 --> H3[load_scan_history]
    H3 --> H4[append ScanHistoryEntry]
    H4 --> H5[keep last 100]
    H5 --> H6[serde_json::to_string_pretty]
    H6 --> H7[std::fs::write history file]

    R1[get_history_summary] --> R2[load_scan_history]
    R2 --> R3[map to HistorySummary]
```

### 5.10 `command_exec.rs` + `app_error.rs`（基础设施）

```mermaid
flowchart LR
    A[module calls run_command*] --> B[std::process::Command]
    B --> C[CommandOutput status stdout stderr]
    C --> D{status / io error kind}
    D --> E1[AppError::CommandUnavailable]
    D --> E2[AppError::CommandPermissionDenied]
    D --> E3[AppError::CommandTimeout]
    D --> E4[AppError::CommandFailed]
    D --> E5[AppError::CommandExecutionFailed]

    E1 --> F[Display to user-readable Chinese message]
    E2 --> F
    E3 --> F
    E4 --> F
    E5 --> F
```

---

## 6. 数据契约结构图（前后端核心对象）

```mermaid
classDiagram
    class PortInfo {
      +u16 port
      +String protocol
      +String address
      +String pid
      +String process
      +String user
      +Option~String~ command
    }

    class ScanResult {
      +String scan_time
      +usize total_ports
      +usize unique_apps
      +Vec~PortInfo~ ports
    }

    class AppGroup {
      +String process
      +String pid
      +Vec~u16~ ports
      +Option~String~ command
    }

    class NetworkDevice {
      +String ip
      +Option~String~ mac
      +Option~String~ hostname
      +bool is_online
    }

    class RemotePort {
      +u16 port
      +bool is_open
      +Option~String~ service
    }

    class DnsQueryResult {
      +String domain
      +String record_type
      +Vec~DnsRecord~ records
      +u64 query_time_ms
      +String dns_server
      +Option~String~ error
    }

    class WhoisResult {
      +String domain
      +Option~String~ registrar
      +Option~String~ created
      +Option~String~ expires
      +Option~String~ updated
      +Vec~String~ status
      +Vec~String~ nameservers
      +Option~String~ dnssec
      +String raw_output
      +Option~String~ error
    }

    class SslCertInfo {
      +String host
      +u16 port
      +String subject
      +String issuer
      +String valid_from
      +String valid_until
      +bool is_valid
      +bool is_expired
      +bool is_self_signed
      +i64 days_until_expiry
      +String signature_algorithm
      +String version
      +String serial_number
      +Option~u32~ key_size
      +Vec~CertChainItem~ certificate_chain
      +String tls_version
      +Option~String~ cipher_suite
      +Option~String~ error
    }

    ScanResult "1" --> "many" PortInfo
    AppGroup "1" --> "many" PortInfo : grouped view by process+pid
    DnsQueryResult "1" --> "many" DnsRecord
    SslCertInfo "1" --> "many" CertChainItem
```

---

## 7. 数据库/持久化结构（文件型“逻辑数据库”）

### 7.1 逻辑 ER 图（`scan_history.json`）

```mermaid
erDiagram
    SCAN_HISTORY_FILE ||--o{ SCAN_HISTORY_ENTRY : contains
    SCAN_HISTORY_ENTRY ||--o{ PORT_INFO : embeds

    SCAN_HISTORY_FILE {
      string path
      string storage_type
    }

    SCAN_HISTORY_ENTRY {
      string timestamp
      int port_count
      int scan_duration_ms
    }

    PORT_INFO {
      int port
      string protocol
      string address
      string pid
      string process
      string user
      string command_nullable
    }
```

### 7.2 历史读写时序图

```mermaid
sequenceDiagram
    participant UI as Frontend
    participant T as tauri_save_to_history
    participant E as export::save_to_history
    participant F as scan_history.json

    UI->>T: invoke(scanResult)
    T->>E: save_to_history(&ScanResult)
    E->>F: read existing history (if exists)
    E->>E: append entry + trim to last 100
    E->>F: write pretty JSON
    E-->>T: Ok/Err
    T-->>UI: Result<(), String>
```

---

## 8. CLI 数据流（独立于 GUI）

```mermaid
flowchart LR
    A[argv parse] --> B{grouped?}
    B -->|yes| C[scan_ports_grouped]
    B -->|no| D[scan_ports]

    C --> E[apply_filter_groups]
    D --> F[apply_filter_ports]

    E --> G{json?}
    F --> H{json?}

    G -->|yes| I[serde_json pretty print]
    G -->|no| J[print_groups]

    H -->|yes| K[serde_json with scan_time total_ports ports]
    H -->|no| L[print_table]
```

---

## 9. 测试与质量数据流

```mermaid
flowchart TD
    A[vitest test] --> B[src/main.test.ts mock invoke contracts]
    A --> C[src/main.dom.test.ts DOM state transitions]
    A --> D[tests/integration/network-lan.e2e.test.ts]

    E[scripts/network-lan-precheck.mjs] --> D
    E --> F[ENV gate RUN_LAN_E2E + LAN_E2E_SUBNET + LAN_E2E_CONFIRM]

    B --> G[验证前后端命令契约字段]
    C --> H[验证 UI 状态与错误提示流]
    D --> I[验证真实内网执行门禁逻辑]
```

---

## 10. 关键事实总结（用于后续评审）

1. 主数据通路是：`UI 事件 -> invoke -> tauri_* -> 模块函数 -> 系统命令/Socket/File -> 结构化结果 -> DOM/Toast`。
2. 错误通路是：`AppError` 统一分类后文本化，前端统一 `reportCommandError` 与 `showToast` 展示。
3. 网络扫描和监测分为两层：
   - 设备发现层：`discover_devices`（ARP + Ping + 主机名）
   - 连通性/端口层：`scan_ports_range`、`ping_one`、`traceroute`
4. 持久化目前仅有导出文件与扫描历史 JSON 文件，无 SQL/NoSQL 实体库。
5. CLI 与 GUI 共享核心扫描逻辑（`core.rs`），只是入口与展示介质不同。
