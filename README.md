# 🔍 Portly

**跨平台端口扫描器 | Cross-platform Port Scanner**

一个现代化的本地端口扫描工具，支持 GUI 和 CLI 双模式，基于 Tauri + Rust 构建。

A modern local port scanning tool with both GUI and CLI modes, built with Tauri + Rust.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)

---

<p align="center">
  <img src="assets/icon.png" width="128" alt="Portly Icon">
</p>

<p align="center">
  <img src="assets/screenshot.png" width="600" alt="Portly Screenshot">
</p>

---

## ✨ Features / 特性

- 🖥️ **Cross-platform / 跨平台** - macOS, Linux, Windows
- 🌓 **Auto Theme / 自动主题** - Follows system dark/light mode / 跟随系统深色/浅色模式
- 📊 **Dual View / 双视图** - Table view & App group view / 表格视图和应用分组视图
- 🔎 **Real-time Filter / 实时过滤** - Filter by app name or port / 按应用名或端口号筛选
- 💻 **GUI + CLI** - Both graphical interface and command line / 图形界面和命令行双模式
- ⚡ **High Performance / 高性能** - Native Rust implementation / Rust 原生实现

---

## 🚀 Installation / 安装

### Download / 下载

Go to [Releases](https://github.com/zots0127/portly/releases) to download for your platform.

前往 [Releases](https://github.com/zots0127/portly/releases) 下载对应平台的安装包。

### Build from Source / 从源码构建

```bash
git clone https://github.com/zots0127/portly.git
cd portly
npm install
npm run tauri build
```

---

## 📖 Usage / 使用方法

### GUI

| Feature | Description |
|---------|-------------|
| Table / Group | Switch between list and grouped view |
| Filter | Filter by app name or port number |
| Command | Show full process command line |
| Hide System | Exclude system processes |

---

## 🧪 Testing / 测试

### 默认测试（Mock）

默认 `npm test` / `npm run test:ui` 走的是 **mock 化测试**，用于验证：

- 数据流与状态更新
- 错误与提示文案一致性
- DOM 渲染与交互回归

该模式不会执行真实网段扫描，不会触发真实内网探测。

### 真实内网端到端（手工）

真实扫描必须在目标内网环境中手工执行。仓库提供了一个环境开关测试入口，避免将内网扫描跑进普通 CI：

- 先运行预检：
  - `npm run precheck:lan-e2e`
- 启用真实内网 E2E：
  `RUN_LAN_E2E=1 LAN_E2E_SUBNET=192.168.1.0/24 LAN_E2E_CONFIRM=YES npm run test:lan-e2e`

说明：

- `RUN_LAN_E2E` 不存在时仅做提示与参数校验，不执行真实扫描。
- 启用时请先确认扫描网段在 `/22~24` 合法范围，并且已连接到对应内网。
- 真实端到端步骤仍以手工验证为主：打开应用、选择网段、观察“已耗时 / 预计还需”提示与异常超时文案。
- `LAN_E2E_CONFIRM=YES` 是最终防误触发确认开关。


### CLI

```bash
portly-cli                    # List all ports / 列出所有端口
portly-cli -g                 # Group by app / 按应用分组
portly-cli -j                 # JSON output / JSON 输出
portly-cli -c                 # Show command / 显示命令行
portly-cli -f docker          # Filter app / 过滤应用
portly-cli -p 8080            # Filter port / 过滤端口
portly-cli -x                 # Exclude system / 排除系统进程
portly-cli -h                 # Help / 帮助
```

---

## 🛠️ Tech Stack / 技术栈

- **Frontend**: TypeScript + Vite
- **Backend**: Rust + Tauri 2.0
- **Styling**: Native CSS with `prefers-color-scheme`

---

## 🗺️ Roadmap

- [x] Cross-platform port scanning / 跨平台端口扫描
- [x] GUI + CLI dual mode / GUI + CLI 双模式
- [x] Auto dark/light theme / 自动深色/浅色主题
- [ ] **Port tunneling to public URL / 本地端口发布到公网地址** 🚀
- [ ] Process kill feature / 进程终止功能
- [ ] Port usage history / 端口使用历史记录

---

## 📄 License

[MIT License](LICENSE) - Copyright (c) 2026 Wang Bojun

---

## 🤝 Contributing / 贡献

Issues and Pull Requests are welcome!

欢迎提交 Issue 和 Pull Request！

---

Made with ❤️ using Tauri + Rust 🦀
