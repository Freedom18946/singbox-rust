// SPDX-License-Identifier: Apache-2.0
use clap::CommandFactory;
use clap_mangen::Man;
use anyhow::Result;
use std::io::Write;

#[derive(clap::Args, Debug)]
pub struct ManArgs {
    /// 输出到文件（默认 stdout）
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
    /// 章节（默认 1，由 mangen 默认处理）
    #[arg(long)]
    pub section: Option<String>,
}

pub fn main(a: ManArgs) -> Result<()> {
    use clap_mangen::Man;
    let cmd = crate::cli::Args::command();
    let mut man = Man::new(cmd);
    if let Some(sec) = a.section.as_ref() {
        man = man.section(sec);
    }
    if let Some(path) = a.out {
        let mut f = std::fs::File::create(path)?;
        man.render(&mut f)?;
    } else {
        let mut buf = Vec::new();
        man.render(&mut buf)?;
        // 在 stdout 模式下，在顶部插入程序名/版本/日期摘要
        let name = env!("CARGO_PKG_NAME");
        let ver = env!("CARGO_PKG_VERSION");
        let date = chrono::Local::now().format("%Y-%m-%d");
        println!(".\\\" {} {} {}", name, ver, date); // 摘要行
        std::io::stdout().write_all(&buf)?;
    }
    Ok(())
}