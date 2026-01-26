# 🔍 Portly

**跨平台端口扫描器 / Cross-platform Port Scanner**

一个现代化的本地端口扫描工具，支持 GUI 和 CLI 双模式，基于 Tauri + Rust 构建。

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)

## ✨ 特性

- 🖥️ **跨平台** - 支持 macOS、Linux、Windows
- 🌓 **自动主题** - 根据系统设置自动切换深色/浅色模式
- 📊 **双视图** - 表格视图 & 应用分组视图
- 🔎 **实时过滤** - 按应用名、端口号快速筛选
- 💻 **GUI + CLI** - 图形界面和命令行工具双模式
- ⚡ **高性能** - Rust 原生实现，快速扫描

## 🚀 安装

### 从 Release 下载

前往 [Releases](https://github.com/kanshan/portly/releases) 下载对应平台的安装包。

### 从源码构建

```bash
git clone https://github.com/kanshan/portly.git
cd portly
npm install
npm run tauri build
```

## 📖 使用方法

### GUI 应用

| 功能 | 说明 |
|------|------|
| 表格/分组 | 切换端口列表显示方式 |
| 搜索框 | 按应用名或端口号过滤 |
| 命令行开关 | 显示进程的完整命令行 |
| 隐藏系统 | 排除系统进程 |

### CLI 命令

```bash
portly-cli                    # 列出所有端口
portly-cli -g                 # 按应用分组
portly-cli -j                 # JSON 输出
portly-cli -c                 # 显示命令行
portly-cli -f docker          # 过滤应用
portly-cli -p 8080            # 过滤端口
portly-cli -x                 # 排除系统进程
```

## 🛠️ 技术栈

- **前端**: TypeScript + Vite
- **后端**: Rust + Tauri 2.0
- **样式**: 原生 CSS（支持 `prefers-color-scheme`）

## 📄 License

[MIT License](LICENSE)

---

Made with ❤️ using Tauri + Rust 🦀
