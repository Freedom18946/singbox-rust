# Powerset 失败组合建议

暂未运行 cargo-hack（网络受限/未安装）。
建议在本机安装后运行：

  cargo install cargo-hack --locked
  cargo hack check --workspace --lib --feature-powerset --depth=2 --keep-going | tee reports/powerset_raw.log

运行完成后，可用提供的 Python 片段生成建议：

  python3 - <<'PY' > reports/powerset_suggestions.md
  # …脚本同指令…
  PY

