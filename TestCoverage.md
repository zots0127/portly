# TestCoverage（测试覆盖文档）

## 1. 当前单元测试覆盖新增情况
1. `src-tauri/src/app_error.rs`：新增 7 个单测，覆盖 `validation`、`command_unavailable`、`command_failed` 的分类映射与显示文本。
2. `src-tauri/src/command_exec.rs`：新增 9 个单测，覆盖 `ensure_command_available` 缺失命令、权限拒绝场景、`run_command` 权限拒绝场景、`run_command_with_timeout` 成功与超时场景、当前进程可用命令、成功输出、非零退出码映射。
3. `src-tauri/src/lib.rs`：新增 17 个单测，覆盖主参数校验函数 `normalize_*`、`to_tauri_error`、`ensure_command_available` 负向校验，以及 `tauri_*` 异步入口在参数非法时的前置返回路径（DNS/Whois/PortRange/Ping/SSL）。
4. `src-tauri/src/network.rs`：新增 `subnet_host_addresses`，新增 `/22~24` 子网边界测试（支持 `/23`），并继续校准无效输入边界逻辑（`resolve_target`）避免系统 DNS 假阳性。
5. `src/error-utils.ts`：新增前端错误文本解析与格式化单测，覆盖字符串、`Error`、对象、JSON 回退与分类关键词断言。
6. `src/main.ts`：前端扫描页和监测页补充手动网段输入与 `/22~24` 本地预校验（UX 层面的用户反馈优化）。
7. `src/network-utils.ts`：补充 `/22~24` 网段合法性、主机数量估算与手工网段优先级解析测试。
8. `src/ui-feedback.ts`：补充 toast 分级文案（success/error/warning/info）可见性与文案关键字回归测试。
9. 补充大范围扫描提示链路的动态耗时覆盖（`已耗时 / 预计还需`）与 DOM 文案可见性。

## 2. 既有测试覆盖点（保留）
1. `src-tauri/src/export.rs` 保有多项序列化、导出格式和历史摘要相关测试。
2. 各扫描/网络/SSL/DNS 模块在既有代码中保持了独立 `#[test]`，可覆盖解析逻辑与边界情况。
3. `src/main.test.ts` 与 `src/main.dom.test.ts` 覆盖前端核心工具函数与主要交互路径。

## 3. 验收目标达成进度
1. 目标：核心错误路径先于功能路径完成可观察测试，当前阶段已覆盖参数校验与命令执行分类主链路，`cargo test` 历史通过过（约 151+ passed），新增 `network` 子网边界测试（`/22~24`）和前端网段预校验场景（`src/main.ts`）需纳入复测。
2. 目标：新增文档与代码同步，当前已新增三份验收文档。
3. 目标：下阶段优先保证每个新增分支都至少有一个失败路径测试和一个成功路径测试。
4. 前端错误提示可读性已开始补齐：`toCommandErrorMessage` 与 `formatCommandErrorMessage` 的前端单测已通过，覆盖分类关键词不回归。

## 4. 下轮补充清单
1. `lib.rs` 的异步命令入口（如 DNS/SSL/Traceroute）补充参数前置校验与错误分类测试。
2. `command_exec::run_command_with_timeout` 覆盖了超时场景；继续补齐权限拒绝模拟边界（高频率拒绝、无输出、非标准返回码）和跨平台一致性验证。
3. `frontend` 新增错误提示断言测试，确认文本中包含错误分类关键词，避免回归。
4. 增加 `src-tauri/src/network.rs` 的隔离式解析失败测试（不依赖系统 DNS 回退策略）和命令级别集成测试，并补齐 `/22` `/23` `/24` 边界扫描路径可观测性。
5. 继续补齐 DOM 级 toast 文案验收测试，连接 `formatCommandErrorMessage` 到真实用户提示场景。
6. 扩展 `src/main.dom.test.ts` 场景覆盖：手工网段输入校验失败提示、`/23~24` 估算耗时提示文案是否出现。
