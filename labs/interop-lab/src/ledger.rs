use crate::case_spec::{load_cases, EnvClass, KernelMode};
use anyhow::{bail, Context, Result};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const S3_HEADING: &str = "## S3:";
const S4_HEADING: &str = "## S4:";
const S6_CURRENT_HEADING: &str = "### Current Metrics";
const S6_PROJECTED_HEADING: &str = "### Projected Coverage";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerMetrics {
    pub total_cases: usize,
    pub both_cases: usize,
    pub strict_both_cases: usize,
    pub total_behaviors: usize,
    pub all_covered_behaviors: usize,
    pub strict_covered_behaviors: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaseLedgerEntry {
    kernel_mode: KernelMode,
    env_class: EnvClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BehaviorRow {
    id: String,
    both_cases: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MarkdownTable {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

pub fn validate_ledger(cases_dir: &Path, spec_path: &Path) -> Result<LedgerMetrics> {
    let cases = load_cases(cases_dir)?;
    let mut case_index = BTreeMap::new();
    for case in cases {
        let id = case.id.clone();
        let old = case_index.insert(
            id.clone(),
            CaseLedgerEntry {
                kernel_mode: case.kernel_mode,
                env_class: case.env_class,
            },
        );
        if old.is_some() {
            bail!("duplicate case id in case inventory: {id}");
        }
    }

    let source = fs::read_to_string(spec_path)
        .with_context(|| format!("reading ledger {}", spec_path.display()))?;
    audit_source(&case_index, &source)
}

fn audit_source(
    case_index: &BTreeMap<String, CaseLedgerEntry>,
    source: &str,
) -> Result<LedgerMetrics> {
    let behaviors = parse_s3_behaviors(source)?;
    let metrics = compute_metrics(case_index, &behaviors)?;
    validate_s6_metrics(source, &metrics)?;
    Ok(metrics)
}

fn compute_metrics(
    case_index: &BTreeMap<String, CaseLedgerEntry>,
    behaviors: &[BehaviorRow],
) -> Result<LedgerMetrics> {
    let both_cases = case_index
        .values()
        .filter(|case| case.kernel_mode == KernelMode::Both)
        .count();
    let strict_both_cases = case_index
        .values()
        .filter(|case| case.kernel_mode == KernelMode::Both && case.env_class == EnvClass::Strict)
        .count();

    let mut all_covered_behaviors = 0usize;
    let mut strict_covered_behaviors = 0usize;
    for behavior in behaviors {
        let mut covered = false;
        let mut strict_covered = false;
        for case_id in &behavior.both_cases {
            let case = case_index.get(case_id).with_context(|| {
                format!("{} references missing Both case `{case_id}`", behavior.id)
            })?;
            if case.kernel_mode != KernelMode::Both {
                bail!(
                    "{} lists `{case_id}` under Both Cases, but case kernel_mode is {:?}",
                    behavior.id,
                    case.kernel_mode
                );
            }
            covered = true;
            strict_covered |= case.env_class == EnvClass::Strict;
        }
        all_covered_behaviors += usize::from(covered);
        strict_covered_behaviors += usize::from(strict_covered);
    }

    Ok(LedgerMetrics {
        total_cases: case_index.len(),
        both_cases,
        strict_both_cases,
        total_behaviors: behaviors.len(),
        all_covered_behaviors,
        strict_covered_behaviors,
    })
}

fn parse_s3_behaviors(source: &str) -> Result<Vec<BehaviorRow>> {
    let s3 = section(source, S3_HEADING, S4_HEADING)?;
    let tables = parse_markdown_tables(s3)?;
    let id_regex = Regex::new(r"^BHV-[A-Z]+-\d{3}$").expect("static BHV regex");
    let mut seen = BTreeSet::new();
    let mut behaviors = Vec::new();

    for table in tables {
        let Some(id_column) = table.headers.iter().position(|header| header == "BHV ID") else {
            continue;
        };
        let Some(both_column) = table
            .headers
            .iter()
            .position(|header| header == "Both Cases")
        else {
            bail!("S3 BHV table is missing Both Cases column");
        };

        for row in table.rows {
            let raw_id = row
                .get(id_column)
                .with_context(|| "S3 BHV table row is missing BHV ID cell")?
                .trim();
            let both_cell = row
                .get(both_column)
                .with_context(|| format!("S3 row `{raw_id}` is missing Both Cases cell"))?
                .trim();
            let (id, struck) = parse_bhv_id(raw_id, &id_regex)?;

            if struck || both_cell.eq_ignore_ascii_case("N/A") {
                if !(struck && both_cell.eq_ignore_ascii_case("N/A")) {
                    bail!("{id} exclusion must use both struck-through BHV ID and N/A Both Cases");
                }
                continue;
            }
            if !seen.insert(id.clone()) {
                bail!("duplicate active BHV row in S3: {id}");
            }

            behaviors.push(BehaviorRow {
                id,
                both_cases: parse_case_references(both_cell)?,
            });
        }
    }

    if behaviors.is_empty() {
        bail!("S3 contains no active BHV rows");
    }
    Ok(behaviors)
}

fn parse_bhv_id(raw: &str, id_regex: &Regex) -> Result<(String, bool)> {
    let raw = raw.trim();
    let struck = raw.starts_with("~~") && raw.ends_with("~~") && raw.len() > 4;
    let inner = if struck {
        raw[2..raw.len() - 2].trim()
    } else {
        raw
    };
    let id = inner.trim_matches('`').to_string();
    if !id_regex.is_match(&id) {
        bail!("invalid BHV ID cell in S3: `{raw}`");
    }
    Ok((id, struck))
}

fn parse_case_references(cell: &str) -> Result<BTreeSet<String>> {
    let trimmed = cell.trim();
    if trimmed.is_empty() || trimmed == "—" || trimmed == "-" {
        return Ok(BTreeSet::new());
    }
    if trimmed.eq_ignore_ascii_case("N/A") {
        bail!("N/A Both Cases is only valid for struck-through S3 rows");
    }

    let mut references = BTreeSet::new();
    let mut chars = trimmed.char_indices().peekable();
    while let Some((start, ch)) = chars.next() {
        if ch != '`' {
            continue;
        }
        let content_start = start + ch.len_utf8();
        let mut end = None;
        for (index, candidate) in chars.by_ref() {
            if candidate == '`' {
                end = Some(index);
                break;
            }
        }
        let end = end.with_context(|| format!("unterminated code span in Both Cases: {cell}"))?;
        let case_id = trimmed[content_start..end].trim();
        if case_id.is_empty() {
            bail!("empty case id in Both Cases: {cell}");
        }
        references.insert(case_id.to_string());
    }

    if references.is_empty() {
        bail!("Both Cases must contain backtick-delimited case ids: {cell}");
    }
    Ok(references)
}

fn validate_s6_metrics(source: &str, metrics: &LedgerMetrics) -> Result<()> {
    let s6 = section(source, S6_CURRENT_HEADING, S6_PROJECTED_HEADING)?;
    let tables = parse_markdown_tables(s6)?;
    let table = tables
        .into_iter()
        .find(|table| {
            table.headers
                == [
                    "Metric".to_string(),
                    "Formula".to_string(),
                    "Value".to_string(),
                ]
        })
        .with_context(|| "S6 Current Metrics table not found")?;

    let mut rows = BTreeMap::new();
    for row in table.rows {
        let metric = row.first().cloned().unwrap_or_default();
        if rows.insert(metric.clone(), row).is_some() {
            bail!("duplicate S6 Current Metrics row: {metric}");
        }
    }

    validate_metric_row(
        &rows,
        "Both-mode case ratio",
        "both cases / total cases",
        metrics.both_cases,
        metrics.total_cases,
    )?;
    validate_metric_row(
        &rows,
        "Behavioral coverage (all)",
        "BHVs with ≥1 both case / total BHVs",
        metrics.all_covered_behaviors,
        metrics.total_behaviors,
    )?;
    validate_metric_row(
        &rows,
        "Behavioral coverage (strict)",
        "BHVs with ≥1 strict both case / total BHVs",
        metrics.strict_covered_behaviors,
        metrics.total_behaviors,
    )?;
    Ok(())
}

fn validate_metric_row(
    rows: &BTreeMap<String, Vec<String>>,
    metric: &str,
    expected_formula: &str,
    numerator: usize,
    denominator: usize,
) -> Result<()> {
    let row = rows
        .get(metric)
        .with_context(|| format!("S6 Current Metrics is missing `{metric}`"))?;
    let formula = row.get(1).map(String::as_str).unwrap_or_default();
    if formula != expected_formula {
        bail!("S6 `{metric}` formula drift: expected `{expected_formula}`, found `{formula}`");
    }

    let value = row.get(2).map(String::as_str).unwrap_or_default();
    let expected = format_metric(numerator, denominator);
    if value != expected {
        bail!("S6 `{metric}` drift: expected `{expected}`, found `{value}`");
    }
    Ok(())
}

fn format_metric(numerator: usize, denominator: usize) -> String {
    let percentage = if denominator == 0 {
        0.0
    } else {
        numerator as f64 * 100.0 / denominator as f64
    };
    format!("{percentage:.1}% ({numerator}/{denominator})")
}

fn section<'a>(source: &'a str, start_heading: &str, end_heading: &str) -> Result<&'a str> {
    let start = source
        .find(start_heading)
        .with_context(|| format!("missing heading `{start_heading}`"))?;
    let after_start = start + start_heading.len();
    let relative_end = source[after_start..]
        .find(end_heading)
        .with_context(|| format!("missing heading `{end_heading}` after `{start_heading}`"))?;
    Ok(&source[after_start..after_start + relative_end])
}

fn parse_markdown_tables(section: &str) -> Result<Vec<MarkdownTable>> {
    let lines: Vec<_> = section.lines().collect();
    let mut tables = Vec::new();
    let mut index = 0usize;

    while index + 1 < lines.len() {
        let header = lines[index].trim();
        let separator = lines[index + 1].trim();
        if !header.starts_with('|') || !separator.starts_with('|') {
            index += 1;
            continue;
        }

        let headers = split_markdown_row(header)?;
        let separators = split_markdown_row(separator)?;
        if headers.len() != separators.len()
            || !separators.iter().all(|cell| is_table_separator(cell))
        {
            index += 1;
            continue;
        }

        index += 2;
        let mut rows = Vec::new();
        while index < lines.len() && lines[index].trim().starts_with('|') {
            let row = split_markdown_row(lines[index].trim())?;
            if row.len() != headers.len() {
                bail!(
                    "markdown table row has {} cells; expected {}: {}",
                    row.len(),
                    headers.len(),
                    lines[index]
                );
            }
            rows.push(row);
            index += 1;
        }
        tables.push(MarkdownTable { headers, rows });
    }

    Ok(tables)
}

fn is_table_separator(cell: &str) -> bool {
    let trimmed = cell.trim().trim_start_matches(':').trim_end_matches(':');
    trimmed.len() >= 3 && trimmed.chars().all(|ch| ch == '-')
}

fn split_markdown_row(line: &str) -> Result<Vec<String>> {
    let line = line.trim();
    if !line.starts_with('|') || !line.ends_with('|') {
        bail!("markdown table row must start and end with `|`: {line}");
    }

    let inner = &line[1..line.len() - 1];
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    let mut in_code = false;
    for ch in inner.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                escaped = true;
                current.push(ch);
            }
            '`' => {
                in_code = !in_code;
                current.push(ch);
            }
            '|' if !in_code => {
                cells.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if escaped {
        bail!("markdown table row ends with an incomplete escape: {line}");
    }
    if in_code {
        bail!("markdown table row has an unterminated code span: {line}");
    }
    cells.push(current.trim().to_string());
    Ok(cells)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn case_yaml(id: &str, kernel_mode: &str, env_class: &str) -> String {
        format!(
            "id: {id}\npriority: p1\nkernel_mode: {kernel_mode}\nenv_class: {env_class}\nbootstrap: {{}}\n"
        )
    }

    fn metric_rows(both: (usize, usize), all: (usize, usize), strict: (usize, usize)) -> String {
        format!(
            "| Metric | Formula | Value |\n\
             |--------|---------|-------|\n\
             | Both-mode case ratio | both cases / total cases | {} |\n\
             | Behavioral coverage (all) | BHVs with ≥1 both case / total BHVs | {} |\n\
             | Behavioral coverage (strict) | BHVs with ≥1 strict both case / total BHVs | {} |\n",
            format_metric(both.0, both.1),
            format_metric(all.0, all.1),
            format_metric(strict.0, strict.1),
        )
    }

    fn spec(rows: &str, metrics: &str) -> String {
        format!(
            "# Ledger\n\
             ## S3: Behavior Registry\n\
             ### DP.1\n\
             | BHV ID | Behavior | Both Cases |\n\
             |--------|----------|------------|\n\
             {rows}\
             \n## S4: Divergence Registry\n\
             content\n\
             ## S6: Coverage Dashboard\n\
             ### Current Metrics\n\
             {metrics}\
             \n### Projected Coverage\n"
        )
    }

    fn fixture(cases: &[(&str, &str, &str)], source: &str) -> (TempDir, LedgerMetrics) {
        let temp = tempfile::tempdir().expect("tempdir");
        let cases_dir = temp.path().join("cases");
        fs::create_dir_all(&cases_dir).expect("cases dir");
        for (id, kernel_mode, env_class) in cases {
            fs::write(
                cases_dir.join(format!("{id}.yaml")),
                case_yaml(id, kernel_mode, env_class),
            )
            .expect("case fixture");
        }
        let spec_path = temp.path().join("golden.md");
        fs::write(&spec_path, source).expect("spec fixture");
        let result = validate_ledger(&cases_dir, &spec_path);
        (temp, result.expect("fixture must validate"))
    }

    #[test]
    fn valid_ledger_computes_case_and_behavior_metrics() {
        let source = spec(
            "| BHV-DP-001 | covered | `both_case`, `both_case` |\n\
             | BHV-DP-002 | gap | — |\n",
            &metric_rows((1, 2), (1, 2), (1, 2)),
        );
        let (_temp, metrics) = fixture(
            &[
                ("both_case", "both", "strict"),
                ("rust_case", "rust", "strict"),
            ],
            &source,
        );
        assert_eq!(
            metrics,
            LedgerMetrics {
                total_cases: 2,
                both_cases: 1,
                strict_both_cases: 1,
                total_behaviors: 2,
                all_covered_behaviors: 1,
                strict_covered_behaviors: 1,
            }
        );
    }

    #[test]
    fn missing_case_reference_fails() {
        let source = spec(
            "| BHV-DP-001 | covered | `missing_case` |\n",
            &metric_rows((1, 1), (1, 1), (1, 1)),
        );
        let temp = tempfile::tempdir().unwrap();
        let cases_dir = temp.path().join("cases");
        fs::create_dir_all(&cases_dir).unwrap();
        fs::write(
            cases_dir.join("both_case.yaml"),
            case_yaml("both_case", "both", "strict"),
        )
        .unwrap();
        let spec_path = temp.path().join("golden.md");
        fs::write(&spec_path, source).unwrap();
        let error = validate_ledger(&cases_dir, &spec_path).unwrap_err();
        assert!(error
            .to_string()
            .contains("missing Both case `missing_case`"));
    }

    #[test]
    fn rust_only_case_listed_as_both_fails() {
        let source = spec(
            "| BHV-DP-001 | covered | `rust_case` |\n",
            &metric_rows((0, 1), (1, 1), (1, 1)),
        );
        let temp = tempfile::tempdir().unwrap();
        let cases_dir = temp.path().join("cases");
        fs::create_dir_all(&cases_dir).unwrap();
        fs::write(
            cases_dir.join("rust_case.yaml"),
            case_yaml("rust_case", "rust", "strict"),
        )
        .unwrap();
        let spec_path = temp.path().join("golden.md");
        fs::write(&spec_path, source).unwrap();
        let error = validate_ledger(&cases_dir, &spec_path).unwrap_err();
        assert!(error.to_string().contains("kernel_mode is Rust"));
    }

    #[test]
    fn strict_case_mark_drift_fails_s6() {
        let source = spec(
            "| BHV-DP-001 | covered | `both_case` |\n",
            &metric_rows((1, 1), (1, 1), (1, 1)),
        );
        let temp = tempfile::tempdir().unwrap();
        let cases_dir = temp.path().join("cases");
        fs::create_dir_all(&cases_dir).unwrap();
        fs::write(
            cases_dir.join("both_case.yaml"),
            case_yaml("both_case", "both", "env_limited"),
        )
        .unwrap();
        let spec_path = temp.path().join("golden.md");
        fs::write(&spec_path, source).unwrap();
        let error = validate_ledger(&cases_dir, &spec_path).unwrap_err();
        assert!(error.to_string().contains("Behavioral coverage (strict)"));
        assert!(error.to_string().contains("0.0% (0/1)"));
    }

    #[test]
    fn duplicate_active_bhv_fails() {
        let source = spec(
            "| BHV-DP-001 | first | `both_case` |\n\
             | BHV-DP-001 | duplicate | `both_case` |\n",
            &metric_rows((1, 1), (1, 1), (1, 1)),
        );
        let temp = tempfile::tempdir().unwrap();
        let cases_dir = temp.path().join("cases");
        fs::create_dir_all(&cases_dir).unwrap();
        fs::write(
            cases_dir.join("both_case.yaml"),
            case_yaml("both_case", "both", "strict"),
        )
        .unwrap();
        let spec_path = temp.path().join("golden.md");
        fs::write(&spec_path, source).unwrap();
        let error = validate_ledger(&cases_dir, &spec_path).unwrap_err();
        assert!(error.to_string().contains("duplicate active BHV"));
    }

    #[test]
    fn struck_sv1_rows_are_excluded_from_denominator() {
        let source = spec(
            "| ~~BHV-SV-001~~ | harness-only | N/A |\n\
             | BHV-DP-001 | covered | `both_case` |\n",
            &metric_rows((1, 1), (1, 1), (1, 1)),
        );
        let (_temp, metrics) = fixture(&[("both_case", "both", "strict")], &source);
        assert_eq!(metrics.total_behaviors, 1);
    }

    #[test]
    fn sv1_row_cannot_enter_documented_denominator() {
        let source = spec(
            "| ~~BHV-SV-001~~ | harness-only | N/A |\n\
             | BHV-DP-001 | covered | `both_case` |\n",
            &metric_rows((1, 1), (1, 2), (1, 2)),
        );
        let temp = tempfile::tempdir().unwrap();
        let cases_dir = temp.path().join("cases");
        fs::create_dir_all(&cases_dir).unwrap();
        fs::write(
            cases_dir.join("both_case.yaml"),
            case_yaml("both_case", "both", "strict"),
        )
        .unwrap();
        let spec_path = temp.path().join("golden.md");
        fs::write(&spec_path, source).unwrap();
        let error = validate_ledger(&cases_dir, &spec_path).unwrap_err();
        assert!(error.to_string().contains("expected `100.0% (1/1)`"));
    }

    #[test]
    fn documented_numerator_or_denominator_drift_fails() {
        let source = spec(
            "| BHV-DP-001 | covered | `both_case` |\n\
             | BHV-DP-002 | structural gap | — |\n",
            &metric_rows((1, 1), (2, 2), (1, 3)),
        );
        let temp = tempfile::tempdir().unwrap();
        let cases_dir = temp.path().join("cases");
        fs::create_dir_all(&cases_dir).unwrap();
        fs::write(
            cases_dir.join("both_case.yaml"),
            case_yaml("both_case", "both", "strict"),
        )
        .unwrap();
        let spec_path = temp.path().join("golden.md");
        fs::write(&spec_path, source).unwrap();
        let error = validate_ledger(&cases_dir, &spec_path).unwrap_err();
        assert!(error.to_string().contains("expected `50.0% (1/2)`"));
    }
}
