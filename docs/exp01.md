````bash
#!/usr/bin/env bash
# CLI 补丁：仅新增文档，不改动任何现有代码/配置
# 作用：生成 doc/e2e_http_405_playbook.md 并导出可 git apply 的补丁
set -Eeuo pipefail
info(){ echo "[INFO] $*"; }; ok(){ echo "[OK]  $*"; }; err(){ echo "[ERR]  $*" >&2; }
need(){ command -v "$1" >/dev/null 2>&1 || { err "missing $1"; exit 127; }; }

need git
mkdir -p doc out

DOC=doc/e2e_http_405_playbook.md

cat > "$DOC" <<'MD'
# e2e HTTP 405 验收脚本踩坑与修正手册（Playbook）

> 适用范围：`scripts/run_and_test.zsh` / `scripts/cli_patch_and_test.sh` 驱动的 HTTP 入站 **405** 与 SOCKS5 **NO_AUTH** 就绪验收。
> 目标：稳定跑通 **编译 → 启动 → 解析动态端口 → HTTP/405 验收 → SOCKS5 验收 → curl 验证 → 指标采样 → 10 连发** 全链路。

---

## 0. 关键前置

- **动态端口**：`config.yaml` 使用 `listen: 127.0.0.1:0`，由内核分配，避免端口冲突。
- **解析实际端口**：从日志解析：
  - HTTP：`HTTP CONNECT bound ... actual=127.0.0.1:<PORT>`
  - SOCKS：`SOCKS5 bound ... actual=127.0.0.1:<PORT>`
  - metrics：`Prometheus metrics exporter listening addr=127.0.0.1:<PORT>`
- **调试开关**：
  - `SB_HTTP_DISABLE_STOP=1` 禁用 stop 打断（测试稳定性用）
  - `RUST_LOG=info` 打印心跳与关键信息（`http: accept-loop heartbeat`）

---

## 1. 坑位清单 → 正确做法

### 1.1 固定端口易冲突 / 并发脚本抢占
- **症状**：`Connection refused`、`Address already in use`，或探针刚跑就失败。
- **根因**：固定端口（如 18081/11080/9900）被残留进程占用；连续跑脚本撞端口。
- **正确做法**：`listen: 127.0.0.1:0`，启动后**从日志解析** `actual=` 端口，并设置 `${HTTP_PROXY_ADDR}` / `${SOCKS_PROXY_ADDR}`：
```sh
HTTP_ACTUAL=$(grep -E "HTTP CONNECT bound .* actual=127\.0\.0\.1:[0-9]+" .e2e/sing.log | tail -n1 | sed -E 's/.*actual=127\.0\.0\.1:([0-9]+).*/\1/')
SOCKS_ACTUAL=$(grep -E "SOCKS5 bound .* actual=127\.0\.0\.1:[0-9]+" .e2e/sing.log | tail -n1 | sed -E 's/.*actual=127\.0\.0\.1:([0-9]+).*/\1/')
export HTTP_PROXY_ADDR="127.0.0.1:${HTTP_ACTUAL}"
export SOCKS_PROXY_ADDR="127.0.0.1:${SOCKS_ACTUAL}"
````

### 1.2 ANSI 控制符污染导致 YAML 解析错误

* **症状**：启动报 `Error: control characters are not allowed at position XX`。
* **根因**：把带 ANSI 颜色的文本误写进 `config.yaml` 或脚本。
* **正确做法**：

  * 配置修改只做**纯文本替换**，不要注入控制符。
  * Perl 捕获组 **务必**用 `${1}0`，避免 `\10` 被当作“第 10 个反向引用”：

```sh
perl -0777 -pe 's/(listen:\s*127\.0\.0\.1:)\d+/${1}0/g' -i config.yaml
```

### 1.3 macOS/BSD 与 GNU 工具差异

* **症状**：`awk: syntax error`、`nc` 参数不支持、BSD `sed` 与 GNU `sed` 不兼容。
* **根因**：脚本用到 GNU-only 语法或 `nc -N` 等不可移植参数。
* **正确做法**：

  * **探针统一用 Python socket**（`probe_http.py` / `probe_socks.py`），避免 `nc`/`curl` 差异影响首行读取。
  * 日志解析尽量用 `grep + sed -E` 的最小子集语法，规避复杂 `awk`。

### 1.4 主实例上做 10 连发引发竞态

* **症状**：单次探针通过，但 10 连发全 `ECONNREFUSED`。
* **根因**：脚本内部的 curl / 其他探针与 10 连发抢同一实例资源，时序敏感。
* **正确做法**：**临时实例（ephemeral）** 专供 10 连发：

  1. 另起进程写 `.e2e/sing.multi.log`；
  2. 从该日志解析 **独立** HTTP 端口；
  3. 仅对该端口做 `probe_http_multi.py 10`；
  4. 结束后 `kill` 收尾。

### 1.5 HTTP 回包序列不严格导致对端空读

* **症状**：偶发探针端读不到 405 首行或被过早关闭。
* **根因**：写后未 flush/立即关闭导致对端未收齐。
* **正确做法**：**严格序列**：`write_all → flush → sleep(10ms) → shutdown`，并**移除调用端重复 shutdown**。

### 1.6 accept-loop 无心跳/被外部打断

* **症状**：无接收、无日志、循环静默退出。
* **根因**：`stop` 信号提前打断；循环无可观测性。
* **正确做法**：

  * 循环顶部起 **heartbeat**，每 500ms 打 `http: accept-loop heartbeat`；
  * 增加 `SB_HTTP_DISABLE_STOP=1` 调试开关；
  * `accept().await` 失败时区分瞬时错误并 **sleep + continue** 重试，避免整体退出。

### 1.7 Perl 捕获组歧义（高危）

* **症状**：`listen` 字段被“删没了”或改坏。
* **根因**：`s/(...)/\10/` 被解析为**第十**反向引用。
* **正确做法**：统一写 `${1}0`，永不使用 `\10`。

### 1.8 失败时的“诊断三件套”

* **收集**：

  1. `.e2e/sing.log` 与（若有）`.e2e/sing.multi.log` 末尾；
  2. 探针输出（HTTP/SOCKS）；
  3. 监听状态：

```sh
lsof -nP -iTCP:<PORT> -sTCP:LISTEN -t 2>/dev/null | xargs -I{} echo "LISTEN {}" || true
netstat -an | grep "<PORT>" || true
```

---

## 2. 快速排障流程（Checklist）

1. **日志就绪**：出现 `HTTP CONNECT bound ... actual=` 与 `SOCKS5 bound ... actual=`。
2. **解析端口**：`HTTP_ACTUAL`/`SOCKS_ACTUAL` 非空；打印 `resolved HTTP=... SOCKS=...`。
3. **HTTP 就绪**：`probe_http.py ${HTTP_PROXY_ADDR} deadline` 返回 `HTTP/1.1 405 ...`。
4. **SOCKS 就绪**：NO\_AUTH 探针通过。
5. **curl 验证**：CONNECT/SOCKS 路径均成功（按脚本场景）。
6. **metrics**（可选）：能抓到 `:9900/metrics` 样本。
7. **10 连发**：仅在临时实例上跑，`[SUMMARY] 10/10 got 405`。

---

## 3. 已知良好日志样例（片段）

```
INFO sb_adapters::inbound::http: HTTP CONNECT bound addr=127.0.0.1:0 actual=127.0.0.1:61821
INFO sb_adapters::inbound::http: http: listener ready local=Some(127.0.0.1:61821)
INFO sb_adapters::inbound::http: http: accept ok peer=127.0.0.1:61825
INFO sb_adapters::inbound::http: http: request line ... method=GET target=/
INFO sb_adapters::inbound::http: http: respond 405 ...
INFO sb_adapters::inbound::http: http: accept-loop heartbeat
```

---

## 4. DOs / DON'Ts

* ✅ 用 `:0`、从日志解析端口；
* ✅ 用 Python socket 做探针；
* ✅ 临时实例跑 10 连发；
* ✅ 失败回收“诊断三件套”；
* ❌ 不要把 ANSI 控制符/彩色日志写入 `config.yaml`；
* ❌ 不要使用 `\10` 形式的反向引用；
* ❌ 不在主实例上和 10 连发相互抢占。

---

## 5. 验收标准（通过即合）

* HTTP：**非 CONNECT 立即 405**，`probe_http.py` 报 OK；
* SOCKS5：**NO\_AUTH** 就绪；
* curl：CONNECT/SOCKS 路径均成功；
* metrics：可选样本成功；
* 临时实例 `probe_http_multi.py ... 10`：**10/10 405**；
* 日志包含**心跳**、**accept ok**、**respond 405** 三类关键线索。

（完）
MD

# 生成补丁

git add "\$DOC"
if ! git diff --cached --quiet; then
git commit -m "docs: e2e HTTP 405 acceptance playbook (pitfalls & fixes)" >/dev/null || true
fi

PATCH=out/docs-e2e-http405-playbook.patch
if ! git diff -p HEAD\~1 HEAD > "\$PATCH" 2>/dev/null; then
git show HEAD > "\$PATCH"
fi

info "doc written: \$DOC"
ok   "patch generated: \$PATCH"

```
::contentReference[oaicite:0]{index=0}
```
