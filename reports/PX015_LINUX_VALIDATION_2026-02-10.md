# PX-015 Linux Runtime/System Bus 双场景验证记录（2026-02-10）

## 1. 目标

闭环 `PX-015` 的 Linux 实机验证（最小闭环）：

- 场景 A：`systemd-resolved` 运行中，抢占 `org.freedesktop.resolve1` 失败且错误明确。
- 场景 B：`systemd-resolved` 停止后，服务可接管并处理 UDP/TCP A/AAAA 查询。

---

## 2. 当前执行环境

- 主机：`Darwin`（非 Linux）
- `systemctl`：不可用
- `busctl`：不可用
- `dig`：可用（`/usr/bin/dig`）

命令证据：

```bash
uname -a
command -v systemctl || true
command -v busctl || true
command -v dig || true
```

结论：当前工作站不满足 Linux/systemd 实机验证前提，无法在本机完成 PX-015 双场景补证。

---

## 3. Linux 主机执行清单（可直接复跑）

### 3.1 准备

```bash
# 构建 parity release（按需）
cargo build -p app --features parity --release
```

### 3.2 场景 A（resolved 运行中）

```bash
systemctl is-active systemd-resolved
busctl --system list | grep org.freedesktop.resolve1 || true
./target/release/app run -c <resolved-config.json> 2>&1 | tee px015_a.log
```

验收点：
- 进程启动失败（非 0）
- 日志包含 `org.freedesktop.resolve1` name 已存在/抢占失败语义

### 3.3 场景 B（resolved 停止后接管）

```bash
sudo systemctl stop systemd-resolved
busctl --system list | grep org.freedesktop.resolve1 || true
./target/release/app run -c <resolved-config.json> 2>&1 | tee px015_b.log
busctl --system list | grep org.freedesktop.resolve1

dig @127.0.0.1 -p <stub_port> example.com A +short
dig @127.0.0.1 -p <stub_port> example.com AAAA +tcp +short
```

验收点：
- 服务成功导出 name
- UDP/TCP DNS 查询均返回有效结果（至少 A/AAAA）

---

## 4. 证据归档要求

- `px015_a.log`
- `px015_b.log`
- `busctl` 输出（场景 A/B）
- `dig` 输出（A/AAAA + TCP）
- 使用的 `<resolved-config.json>` 摘要（隐藏敏感信息）

建议将 Linux 主机证据同步到：
- `reports/PX015_LINUX_VALIDATION_2026-02-10.md`（本文件追加结果）
- `agents-only/02-reference/GO_PARITY_MATRIX.md`（更新 PX-015 状态）

---

## 5. 当前状态判定（2026-02-24 决议更新）

- `PX-015` 状态：`ACCEPTED LIMITATION`（Linux 实机补证不再作为开放阻塞项）
- `Parity Remaining`：`0`（本项保留历史证据，不再继续追踪）
