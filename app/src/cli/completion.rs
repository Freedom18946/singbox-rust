// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::undocumented_unsafe_blocks
    )
)]
use anyhow::{Context, Result};
use clap::{Args as ClapArgs, CommandFactory, ValueEnum};
use clap_complete::{generate, shells};
use std::io;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
    Elvish,
}

#[derive(ClapArgs, Debug)]
pub struct CompletionArgs {
    /// 目标 shell
    #[arg(long, value_enum)]
    pub shell: Shell,
    /// 输出目录（默认 stdout）
    #[arg(long)]
    pub dir: Option<std::path::PathBuf>,
    /// 一键生成全部 shell（需配合 --dir）
    #[arg(long)]
    pub all: bool,
}

pub fn main(a: CompletionArgs) -> Result<()> {
    let mut cmd = crate::cli::Args::command();
    let bin = std::env::var("SB_CLI_BIN").unwrap_or_else(|_| cmd.get_name().to_string());
    if let Some(ref dir) = a.dir {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create completion output dir {:?}", dir))?;
        let path = |shell_name: &str| dir.join(format!("{}_{}.completion", bin, shell_name));
        macro_rules! write_file {
            ($sh:expr, $name:expr) => {{
                let mut f = std::fs::File::create(path($name))?;
                clap_complete::generate($sh, &mut cmd, &bin, &mut f);
                Ok::<_, anyhow::Error>(())
            }};
        }
        if a.all {
            write_file!(shells::Bash, "bash")?;
            write_file!(shells::Zsh, "zsh")?;
            write_file!(shells::Fish, "fish")?;
            write_file!(shells::PowerShell, "powershell")?;
            write_file!(shells::Elvish, "elvish")?;
            eprintln!("# completions written to {}", dir.display());
        } else {
            match a.shell {
                Shell::Bash => {
                    write_file!(shells::Bash, "bash")?;
                }
                Shell::Zsh => {
                    write_file!(shells::Zsh, "zsh")?;
                }
                Shell::Fish => {
                    write_file!(shells::Fish, "fish")?;
                }
                Shell::PowerShell => {
                    write_file!(shells::PowerShell, "powershell")?;
                }
                Shell::Elvish => {
                    write_file!(shells::Elvish, "elvish")?;
                }
            }
        }
    } else {
        match a.shell {
            Shell::Bash => generate(shells::Bash, &mut cmd, &bin, &mut io::stdout()),
            Shell::Zsh => generate(shells::Zsh, &mut cmd, &bin, &mut io::stdout()),
            Shell::Fish => generate(shells::Fish, &mut cmd, &bin, &mut io::stdout()),
            Shell::PowerShell => generate(shells::PowerShell, &mut cmd, &bin, &mut io::stdout()),
            Shell::Elvish => generate(shells::Elvish, &mut cmd, &bin, &mut io::stdout()),
        }
    }
    // 追加安装提示
    print_install_hints(&a);
    Ok(())
}

fn print_install_hints(_a: &CompletionArgs) {
    use std::env;
    let exe = env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "app".into());
    eprintln!("# install hints (macOS/Linux)");
    eprintln!(
        "# Bash   : ~/.bashrc    -> source <(./{} gen-completions --shell bash)",
        exe
    );
    eprintln!(
        "# Zsh    : ~/.zshrc     -> source <(./{} gen-completions --shell zsh)",
        exe
    );
    eprintln!(
        "# Fish   : ~/.config/fish/completions/{}.fish  (mkdir -p 其目录后拷贝生成文件)",
        exe
    );
    eprintln!("# PowerSh: $PROFILE     -> 取生成的 ps1 并 dot-source");
    eprintln!(
        "# Elvish : ~/.elvish/lib/completions/{}.elv (拷贝后 use completions/{})",
        exe, exe
    );
}
