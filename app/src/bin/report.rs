use app::cli::report::{self, Args};
use clap::Parser;

fn main() {
    let args = Args::parse();
    if let Err(e) = report::main(args) {
        eprintln!(r#"{{"ok":false,"error":"{}"}}"#, e);
        std::process::exit(1);
    }
}