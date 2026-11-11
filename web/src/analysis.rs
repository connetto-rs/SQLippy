//! Runs SQLippy over the text in the editor and flattens what it reports into
//! plain data the page renders.

use sqlippy::prelude::*;
use sqlparser::{ast::Statement, dialect::PostgreSqlDialect, parser::Parser};

/// One rule violation, detached from the parsed database it was raised on.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// Level the violation was raised at.
    pub level: Level,
    /// The rule's name, its configuration key.
    pub rule: &'static str,
    /// The rule's group.
    pub group: LintGroup,
    /// Why the flagged shape is bad.
    pub rationale: &'static str,
    /// URL of a source documenting the problem.
    pub source: Option<&'static str>,
    /// Whether the rule decides from declared structure or guesses from names.
    pub basis: Basis,
    /// Name of the offending schema object.
    pub object: String,
    /// What is wrong with the object.
    pub message: String,
    /// The corrected shape.
    pub resolution: String,
    /// Policy clauses or the application statement the finding points into.
    pub sites: Vec<String>,
}

/// Everything SQLippy reported about one input.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    /// Violations, `deny` before `warn`, each level in rule order.
    pub findings: Vec<Finding>,
    /// Schema objects a rule needed and could not resolve.
    pub lookups: Vec<String>,
    /// Number of application statements checked with the query rules.
    pub statements: usize,
}

/// Why the input could not be checked.
#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    /// The text is not PostgreSQL.
    #[error("the SQL does not parse: {0}")]
    Parse(#[from] sqlparser::parser::ParserError),
    /// The statements parse but do not describe a consistent schema.
    #[error("the schema is not consistent: {0}")]
    Schema(#[from] sql_traits::errors::Error),
}

/// Whether a statement is one an application sends rather than schema DDL.
fn is_application_statement(statement: &Statement) -> bool {
    matches!(
        statement,
        Statement::Query(_)
            | Statement::Insert(_)
            | Statement::Update(_)
            | Statement::Delete(_)
            | Statement::Merge(_)
    )
}

/// Moves one diagnostic into `report`.
fn record(report: &mut Report, error: Error<ParserDB>) {
    match error {
        Error::Violation(violation) => {
            let sites = match violation.location() {
                Location::Policies(sites) => sites.iter().map(ToString::to_string).collect(),
                Location::Statement(site) => {
                    vec![format!("{} in {}", site.expression(), site.statement())]
                }
                _ => Vec::new(),
            };
            let metadata = violation.rule();
            report.findings.push(Finding {
                level: violation.level(),
                rule: metadata.name,
                group: metadata.group,
                rationale: metadata.rationale,
                source: metadata.source,
                basis: metadata.basis,
                object: violation.object().to_owned(),
                message: violation.message().to_owned(),
                resolution: violation.resolution().to_owned(),
                sites,
            });
        }
        Error::Lookup(error) => report.lookups.push(error.to_string()),
        // The page registers no allowances and declares every deployment
        // fact the rules read, so neither of these can arise.
        Error::UnusedAllowance(_) | Error::Inactive(_) => {}
    }
}

/// Checks the schema DDL and the application statements in `sql` with
/// `constrainer`.
///
/// Schema statements build the database the rules read. `SELECT`, `INSERT`,
/// `UPDATE`, `DELETE` and `MERGE` statements are checked against it with the
/// query rules.
///
/// # Errors
///
/// Returns [`AnalysisError::Parse`] when `sql` is not PostgreSQL, and
/// [`AnalysisError::Schema`] when its DDL does not build a schema.
pub fn analyze(
    sql: &str,
    constrainer: &DefaultConstrainer<ParserDB>,
) -> Result<Report, AnalysisError> {
    let statements: Vec<Statement> = Parser::parse_sql(&PostgreSqlDialect {}, sql)?
        .into_iter()
        .filter(is_application_statement)
        .collect();
    let database = ParserDB::parse::<PostgreSqlDialect>(sql)?;
    let mut report = Report {
        statements: statements.len(),
        ..Report::default()
    };
    for error in constrainer.diagnostics(&database) {
        record(&mut report, error);
    }
    for statement in &statements {
        for error in constrainer.statement_diagnostics(&database, statement) {
            record(&mut report, error);
        }
    }
    report
        .findings
        .sort_by_key(|finding| std::cmp::Reverse(finding.level));
    Ok(report)
}
