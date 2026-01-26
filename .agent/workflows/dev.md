---
description: 启动 Portly 开发服务器
---

# 启动 Portly 开发服务器

// turbo-all

1. 进入项目目录并启动开发服务器

```bash
cd /Users/kanshan/localports/portly && npm run tauri dev
```

开发服务器启动后，Portly 应用会自动打开。

## 其他常用命令

- **构建发布版本**: `npm run tauri build`
- **只编译 Rust**: `cd src-tauri && cargo build --release`
- **运行 CLI**: `cd src-tauri && cargo run --bin portly-cli`
