#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: router proxy bridge (decision→route)"

# 1) 启用规则：example.com 走 proxy，其余 direct
export SB_ROUTER_RULES_ENABLE=1
export SB_ROUTER_RULES_TEXT='suffix:.example.com = proxy
default = direct'

# 2) 默认代理：如未提供，保持 direct（不会破坏）
# 要测试代理路径，请显式设置如下其一：
# export SB_ROUTER_DEFAULT_PROXY="http://127.0.0.1:3128"
# export SB_ROUTER_DEFAULT_PROXY="socks5://127.0.0.1:1080"
echo "[INFO] DEFAULT PROXY = ${SB_ROUTER_DEFAULT_PROXY:-direct}"

# 3) 只校验路由决策与指标是否上报，不强依赖公网可达
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}
HTTP=${HTTP:-127.0.0.1:18081}

set +e
curl -sv -x http://$HTTP http://www.example.com/ -o /dev/null 2>&1 | tail -n3
set -e

echo "[SCRAPE] /metrics (optional)"
set +e
curl -s "http://${SB_METRICS_ADDR}/metrics" | grep -E 'router_route_total' && \
  echo "[OK] router_route_total present" || echo "[WARN] metrics not visible"
set -e
echo "[DONE]"