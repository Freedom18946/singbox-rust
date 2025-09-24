#![cfg_attr(feature = "strict_warnings", deny(warnings))]
//! sb-dsl：DSL+ 工具（expand/lint/pack），纯离线。
//! 依赖：features = ["dsl_plus","preview_route"]
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name = "sb-dsl", version, about = "DSL+ toolbox (offline)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// 展开 include/macro，输出标准 DSL 文本
    Expand {
        /// 输入 DSL(+) 文件
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        /// 输出到文件（省略则打印到 stdout）
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },
    /// 校验：尝试构建 RouterIndex，并输出统计
    Lint {
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        /// 显示扩展后的 DSL（仅调试）
        #[arg(long, default_value_t = false)]
        show: bool,
    },
    /// 打包：将展开后的 DSL 写入目标文件（覆盖）
    Pack {
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Expand { input, output } => {
            let txt = fs::read_to_string(&input)
                .map_err(|e| anyhow!("无法读取 {}: {e}", input.display()))?;
            let cwd = input.parent();
            let out = sb_core::router::dsl_plus::expand_dsl_plus(&txt, cwd)
                .map_err(|e| anyhow!("展开失败: {e}"))?;
            if let Some(p) = output {
                fs::write(&p, out).map_err(|e| anyhow!("写入 {} 失败: {e}", p.display()))?;
            } else {
                println!("{out}");
            }
        }
        Cmd::Lint { input, show } => {
            let txt = fs::read_to_string(&input)
                .map_err(|e| anyhow!("无法读取 {}: {e}", input.display()))?;
            let cwd = input.parent();
            let expanded = sb_core::router::dsl_plus::expand_dsl_plus(&txt, cwd)
                .map_err(|e| anyhow!("展开失败: {e}"))?;
            let idx = sb_core::router::preview::build_index_from_rules(&expanded)
                .map_err(|e| anyhow!("构建失败: {e}"))?;
            // 只输出简短统计；真正的结构细节交给现有 explain/preview
            let (mut exact, mut suffix, mut dft, mut others) = (0, 0, 0, 0);
            for line in expanded.lines() {
                let t = line.trim();
                if t.starts_with("exact:") {
                    exact += 1;
                } else if t.starts_with("suffix:") {
                    suffix += 1;
                } else if t.starts_with("default:") {
                    dft += 1;
                } else {
                    others += 1;
                }
            }
            println!(
                "LINT_OK: rules_total={} exact={} suffix={} default={} others={}",
                exact + suffix + dft + others,
                exact,
                suffix,
                dft,
                others
            );
            if show {
                println!("--- EXPANDED ---\n{expanded}");
            }
            // 防止未使用警告
            let _ = idx; // build 仅用于校验
        }
        Cmd::Pack { input, output } => {
            let txt = fs::read_to_string(&input)
                .map_err(|e| anyhow!("无法读取 {}: {e}", input.display()))?;
            let cwd = input.parent();
            let out = sb_core::router::dsl_plus::expand_dsl_plus(&txt, cwd)
                .map_err(|e| anyhow!("展开失败: {e}"))?;
            fs::write(&output, out).map_err(|e| anyhow!("写入 {} 失败: {e}", output.display()))?;
            println!("PACK_OK: {}", output.display());
        }
    }
    Ok(())
}
