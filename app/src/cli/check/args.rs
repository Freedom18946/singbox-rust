use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct CheckArgs {
    /// Config file path (YAML/JSON). Use '-' for stdin.
    #[arg(short = 'c', long = "config")]
    pub config: String,
    /// Output format: human | json | sarif
    #[arg(long, default_value = "text", value_parser = ["text", "json", "sarif"])]
    pub format: String,
    /// Treat warnings as errors
    #[arg(long)]
    pub strict: bool,
    /// Enable v1 JSON-Schema validation
    #[arg(long)]
    pub schema: bool,
    /// Dump schema: v1 (hand), v2 (schemars). Requires --schema.
    #[arg(long = "schema-dump", value_parser = ["v1","v2"], default_value="v1")]
    pub schema_dump: String,
    /// Check reference files (rules_text/rules_json/*file/*path)
    #[arg(long = "check-refs")]
    pub check_refs: bool,
    /// Max reference file size in bytes (default 256 KiB)
    #[arg(long = "max-ref-size", default_value_t = 262144)]
    pub max_ref_size: usize,
    /// Deny unknown fields (strict schema)
    #[arg(long = "deny-unknown")]
    pub deny_unknown: bool,
    /// Allow unknown fields under JSON Pointer prefixes (comma-separated), e.g. '/dns/custom,/experimental'
    #[arg(long = "allow-unknown")]
    pub allow_unknown: Option<String>,
    /// Suggest fixes in human format
    #[arg(long)]
    pub explain: bool,
    /// Enforce apiversion/kind presence and sanity (advisory unless --strict)
    #[arg(long = "enforce-apiversion")]
    pub enforce_apiversion: bool,
    /// Emit canonical JSON and SHA256 fingerprint into report (no IO)
    #[arg(long = "fingerprint")]
    pub fingerprint: bool,
    /// Print only the config fingerprint (SHA256-8 hex) and exit
    #[arg(long = "print-fingerprint")]
    pub print_fingerprint: bool,
    /// Root directory for resolving rules_* and *file/*path refs
    #[arg(long = "rules-dir")]
    pub rules_dir: Option<PathBuf>,
    /// Print normalized config (canonical object keys, rule reordering, deduped domain/cidr). No file writes.
    #[arg(long)]
    pub normalize: bool,
    /// Emit a JSON Patch-style autofix plan (move/replace) to make rules effective. No file writes.
    #[arg(long = "autofix-plan")]
    pub autofix_plan: bool,
    /// Print a one-line human summary (counts, ports, pools)
    #[arg(long)]
    pub summary: bool,
    /// Explainability: print why a rule is unreachable/empty (dimension-level cause)
    #[arg(long = "why")]
    pub explain_why: bool,
    /// Emit DOT graph of rule coverage/shadow edges (stdout). No file writes.
    #[arg(long = "rule-graph")]
    pub rule_graph: bool,
    /// Output minimized config (remove rules fully covered by earlier ones, keep order by specificity).
    #[arg(long = "minimize-rules-output")]
    pub minimize_rules: bool,
    /// Apply a JSON-Patch plan (from stdin) to the loaded config and print result to stdout. No file writes.
    #[arg(long = "apply-plan")]
    pub apply_plan: bool,
    /// Attach stable RuleID (sha256-8) to issues/graph to help mapping after reorder/minimize
    #[arg(long = "with-rule-id")]
    pub with_rule_id: bool,
    /// Compare two configs (canonical) and print rule-level diff using RuleID
    #[arg(long = "diff-config", value_names = ["OLD","NEW"])]
    pub diff_config: Vec<String>,
    /// Validate config against strong typed Schema v2 (feature: schema-v2). Automatically enabled with --deny-unknown.
    #[arg(long = "schema-v2-validate")]
    pub schema_v2: bool,
    /// Try to minimize rules (dedup/merge/etc.)
    #[arg(long = "minimize-rules", default_value_t = false)]
    pub minimize: bool,
    /// Write normalized (or minimized) config IR dump (JSON)
    #[arg(long = "write-normalized", default_value_t = false)]
    pub write_normalized: bool,
    /// Output file for --write-normalized (default: <config>.normalized.json)
    #[arg(long = "out")]
    pub out: Option<String>,
}
