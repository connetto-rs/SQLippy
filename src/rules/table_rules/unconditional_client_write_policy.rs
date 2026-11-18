//! Submodule providing the `UnconditionalClientWritePolicy` rule.

use std::collections::BTreeSet;

use sql_traits::{
    errors::LookupError,
    structs::{IdentifierCase, TriggerEnablement},
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, PolicyLike, TableLike, TriggerLike},
};
use sqlparser::ast::{
    CreatePolicyType, Expr, Ident, ObjectName, ObjectNamePart, Query, SetExpr, Statement,
    TableObject, TriggerPeriod, Value,
};
use sqlparser_plpgsql::embedded::{AliasTarget, Block, DeclarationKind, Node, NodeKind};

use crate::{
    deployment::{Declaration, Deployment},
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::stored_table,
        plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
        policy_support::{Command, Stage, applied, applies_to, held_by_name, is_tautology},
        trigger_support::{fires_on_insert, row, row_trigger},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

rule_definition!(
    /// Struct defining a rule that reports a permissive `INSERT`, `UPDATE`,
    /// `DELETE` or `ALL` policy through which a client role writes every row.
    ///
    /// For each write the rule reads the clause PostgreSQL applies: `WITH
    /// CHECK`, or `USING` in its place, for the rows `INSERT` adds, and `USING`
    /// for the rows `UPDATE` and `DELETE` reach. The policy is reported when
    /// that clause is true for every row and it applies to a declared app
    /// role or, while the deployment declares no credential, to `PUBLIC` or a
    /// declared anonymous role, unless a restrictive policy on that role and
    /// command limits the rows. `credential_free_write` judges anonymous
    /// callers once a credential is declared, `tautological_policy` judges a
    /// `USING` true through an always-true operand, and
    /// `tautological_with_check` judges an always-true `WITH CHECK` beside a
    /// row-dependent `USING`, so this rule reads only a literal-true `USING`.
    /// A `SELECT` policy reading `USING (true)` is a deliberate public read
    /// and is not judged.
    ///
    /// An `INSERT` is not judged on a table whose new rows name only rows
    /// their own statement creates, which holds when the table has a minted
    /// foreign key and every column belongs to one or is generated. A foreign
    /// key is minted when an enabled row-level `AFTER INSERT` trigger without
    /// a `WHEN` condition runs a PL/pgSQL function that, on every path
    /// returning, inserts one `VALUES` row into the referenced table with
    /// `NEW`'s value of each host column for its referenced column, without
    /// `ON CONFLICT` and outside any exception handler that catches its
    /// failure. The referenced columns are unique, so that insert fails
    /// whenever a row already holds the key. A function writing or shadowing
    /// `NEW`, and a referenced table with an enabled `BEFORE INSERT` row
    /// trigger, which may skip the insert, mint nothing.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> =
    ///     UnconditionalClientWritePolicy::default().into();
    /// constrainer.set_deployment(Deployment::default().with_app_role("member"));
    /// let schema = "CREATE ROLE member; CREATE TABLE docs (id INT, owner TEXT);
    ///               ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";
    ///
    /// let open = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} CREATE POLICY d ON docs FOR DELETE TO member USING (true);"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&open).is_err());
    ///
    /// let owned = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} CREATE POLICY d ON docs FOR DELETE TO member USING (owner = current_user);"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&owned).is_ok());
    /// ```
    UnconditionalClientWritePolicy,
    register_table_rule,
    LintGroup::Suspicious,
    "Signing in does not entitle a client to every tenant's rows, so a write policy true for every row lets any client role insert, change or delete rows that belong to others.",
    Some("https://github.com/supabase/splinter/blob/main/lints/0024_rls_policy_always_true.sql"),
    RuleExample {
        bad: "CREATE ROLE authenticated NOLOGIN;\n\
CREATE TABLE public.documents (identifier INT PRIMARY KEY, owner_name TEXT);\n\
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;\n\
GRANT DELETE ON public.documents TO authenticated;\n\
CREATE POLICY delete_documents ON public.documents FOR DELETE TO authenticated USING (true);",
        good: "CREATE ROLE authenticated NOLOGIN;\n\
CREATE TABLE public.documents (identifier INT PRIMARY KEY, owner_name TEXT);\n\
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;\n\
GRANT DELETE ON public.documents TO authenticated;\n\
CREATE POLICY delete_documents ON public.documents FOR DELETE TO authenticated\n\
USING (owner_name = current_user);",
    },
    Basis::Declared
);

/// The writes judged, with their keyword and the stage whose rows a client
/// chooses: new rows for `INSERT`, existing rows for `UPDATE` and `DELETE`.
const WRITES: [(Command, &str, Stage); 3] = [
    (Command::Insert, "INSERT", Stage::Check),
    (Command::Update, "UPDATE", Stage::Filter),
    (Command::Delete, "DELETE", Stage::Filter),
];

/// Whether the expression is the literal `true`, parentheses aside.
fn is_literal_true(expression: &Expr) -> bool {
    match expression {
        Expr::Nested(inner) => is_literal_true(inner),
        Expr::Value(literal) => matches!(literal.value, Value::Boolean(true)),
        _ => false,
    }
}

/// Whether `column` is the one `ident` names.
fn named<C: ColumnLike>(column: &C, ident: &Ident) -> bool {
    IdentifierCase::AsWritten.identifiers_match(
        column.column_name(),
        column.column_name_is_quoted(),
        &ident.value,
        ident.quote_style.is_some(),
    )
}

/// Whether the expression, under parentheses, is `NEW.column`.
fn is_new_field<C: ColumnLike>(expression: &Expr, column: &C) -> bool {
    match expression {
        Expr::Nested(inner) => is_new_field(inner, column),
        Expr::CompoundIdentifier(parts) => matches!(
            parts.as_slice(),
            [record, field] if row(record) == Some(true) && named(column, field)
        ),
        _ => false,
    }
}

/// Whether a part of `name` is `NEW`.
fn names_new(name: &ObjectName) -> bool {
    name.0
        .iter()
        .filter_map(ObjectNamePart::as_ident)
        .any(|part| row(part) == Some(true))
}

/// Whether every path reaching a step has inserted the referenced row.
#[derive(Clone, Copy)]
struct Minted(bool);

impl FlowState for Minted {
    fn join(&mut self, other: Self) {
        self.0 &= other.0;
    }
}

/// Follows a trigger function's paths to whether each one returning has
/// inserted the row a foreign key references with `NEW`'s key.
struct Minting<'m, 'db, DB: DatabaseLike> {
    database: &'db DB,
    /// The table the foreign key references.
    referenced: &'db DB::Table,
    /// The referenced table's columns, in the order an insert naming none
    /// fills them.
    order: &'m [&'db DB::Column],
    /// Each referenced column, with the host column whose `NEW` value it
    /// receives.
    pairs: &'m [(&'db DB::Column, &'db DB::Column)],
    /// Some path returns without having inserted the row.
    unminted: bool,
    /// The function writes `NEW` or gives the name to another variable.
    unfollowed: bool,
}

impl<DB: DatabaseLike> Minting<'_, '_, DB> {
    /// Whether `statement` inserts the referenced row from `NEW`'s key,
    /// failing when a row already holds it.
    fn mints(&self, statement: &Statement) -> bool {
        if let Statement::Insert(insert) = statement
            && let TableObject::TableName(name) = &insert.table
            && let Some(source) = insert.source.as_deref()
            && let SetExpr::Values(values) = source.body.as_ref()
            && let [values] = values.rows.as_slice()
            && insert.on.is_none()
            && insert.or.is_none()
            && !insert.ignore
            && source.with.is_none()
            && source.limit_clause.is_none()
            && source.fetch.is_none()
            && matches!(
                stored_table(self.database, name, None),
                Ok(Some(table)) if table == self.referenced
            )
        {
            return self.pairs.iter().all(|&(referenced, host)| {
                let at = if insert.columns.is_empty() {
                    self.order.iter().position(|column| *column == referenced)
                } else {
                    insert.columns.iter().position(|column| {
                        column
                            .0
                            .last()
                            .and_then(ObjectNamePart::as_ident)
                            .is_some_and(|ident| named(referenced, ident))
                    })
                };
                at.and_then(|at| values.get(at))
                    .is_some_and(|value| is_new_field(value, host))
            });
        }
        false
    }
}

impl<DB: DatabaseLike> FlowVisitor for Minting<'_, '_, DB> {
    type State = Minted;

    fn enter(&mut self, block: &Block, _state: &mut Minted) {
        self.unfollowed |= block.declarations.iter().any(|declaration| {
            declaration.name == "new"
                || matches!(&declaration.kind, DeclarationKind::Alias(AliasTarget::Name(name)) if names_new(name))
        });
    }

    fn query(&mut self, _query: &Query, _state: &mut Minted) {}

    fn statement(&mut self, statement: &Statement, state: &mut Minted) {
        state.0 |= self.mints(statement);
    }

    fn step(&mut self, node: &Node, state: &mut Minted) {
        let written = match &node.kind {
            NodeKind::Return { .. } => {
                self.unminted |= !state.0;
                return;
            }
            NodeKind::Assignment(assignment) => names_new(&assignment.target.name),
            NodeKind::Statement {
                into: Some(into), ..
            }
            | NodeKind::Dynamic {
                into: Some(into), ..
            } => into.targets.iter().any(|target| names_new(&target.name)),
            NodeKind::Fetch(fetch) => fetch.targets.iter().any(|target| names_new(&target.name)),
            NodeKind::Diagnostics(diagnostics) => diagnostics
                .items
                .iter()
                .any(|item| names_new(&item.target.name)),
            _ => false,
        };
        self.unfollowed |= written;
    }
}

/// Whether a trigger fires in the `origin` sessions clients write in.
fn enabled<DB: DatabaseLike>(database: &DB, trigger: &DB::Trigger) -> Result<bool, LookupError> {
    Ok(matches!(
        trigger.enablement(database)?,
        TriggerEnablement::Origin | TriggerEnablement::Always
    ))
}

/// Whether a trigger on `table` mints `foreign_key`, inserting the row it
/// references from each new row's key.
fn minted<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    foreign_key: &DB::ForeignKey,
) -> Result<bool, LookupError> {
    let referenced = foreign_key.referenced_table(database)?;
    for trigger in referenced.triggers(database)? {
        if row_trigger(trigger, TriggerPeriod::Before)
            && fires_on_insert(trigger)
            && enabled(database, trigger)?
        {
            return Ok(false);
        }
    }
    let order: Vec<_> = referenced.columns(database)?.collect();
    let pairs: Vec<_> = foreign_key
        .referenced_columns(database)?
        .zip(foreign_key.host_columns(database)?)
        .collect();
    for trigger in table.triggers(database)? {
        if row_trigger(trigger, TriggerPeriod::After)
            && fires_on_insert(trigger)
            && trigger.condition().is_none()
            && enabled(database, trigger)?
            && let Some(block) = trigger.function(database).and_then(plpgsql_block)
        {
            let mut minting = Minting {
                database,
                referenced,
                order: &order,
                pairs: &pairs,
                unminted: false,
                unfollowed: false,
            };
            walk_block(&mut minting, &block, Minted(false));
            if !minting.unminted && !minting.unfollowed {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Whether every row an `INSERT` adds to `table` names only rows its own
/// statement creates, since some foreign key is minted and every column is a
/// column of a minted foreign key or generated.
fn mints_new_rows<DB: DatabaseLike>(database: &DB, table: &DB::Table) -> Result<bool, LookupError> {
    let mut minted_columns = Vec::new();
    for foreign_key in table.foreign_keys(database)? {
        if minted(database, table, foreign_key)? {
            minted_columns.extend(foreign_key.host_columns(database)?);
        }
    }
    Ok(!minted_columns.is_empty()
        && table.columns(database)?.all(|column| {
            column.generation_expression().is_some() || minted_columns.contains(&column)
        }))
}

/// The client callers judged, each named for messages with the roles it
/// holds: every declared app role, and while no credential is declared, each
/// declared anonymous role and a caller holding only `PUBLIC`.
fn client_callers<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
) -> Vec<(String, BTreeSet<String>)> {
    let mut callers: Vec<_> = deployment
        .app_roles()
        .map(|role| (format!("role '{role}'"), held_by_name(database, role)))
        .collect();
    if !deployment.declares(Declaration::Credentials) {
        callers.extend(
            deployment
                .anonymous_roles()
                .map(|role| (format!("role '{role}'"), held_by_name(database, role))),
        );
        callers.push(("PUBLIC".to_owned(), BTreeSet::new()));
    }
    callers
}

impl<DB: DatabaseLike> TableRule for UnconditionalClientWritePolicy<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !table.has_row_level_security(database)? {
            return Ok(());
        }
        let callers = client_callers(database, reporter.deployment());
        let policies: Vec<_> = table.policies(database)?.collect();
        let mut unguarded: Vec<(Command, &str)> = Vec::new();
        for (command, _, stage) in WRITES {
            'callers: for (label, held) in &callers {
                for policy in &policies {
                    if policy.policy_type() != CreatePolicyType::Restrictive
                        || !command.covered_by(policy.command())
                        || !applies_to(database, *policy, held)
                    {
                        continue;
                    }
                    for clause in applied(database, *policy, command)? {
                        if clause.stage == stage
                            && !is_tautology(database, table, clause.expression)?
                        {
                            continue 'callers;
                        }
                    }
                }
                unguarded.push((command, label));
            }
        }
        if unguarded
            .iter()
            .any(|(command, _)| *command == Command::Insert)
            && mints_new_rows(database, table)?
        {
            unguarded.retain(|(command, _)| *command != Command::Insert);
        }
        for policy in &policies {
            if policy.policy_type() == CreatePolicyType::Restrictive {
                continue;
            }
            let mut commands = Vec::new();
            let mut writers = BTreeSet::new();
            let mut sites: Vec<PolicySite<DB>> = Vec::new();
            for (command, keyword, stage) in WRITES {
                if !command.covered_by(policy.command()) {
                    continue;
                }
                let reached: Vec<&str> = callers
                    .iter()
                    .filter(|(label, held)| {
                        applies_to(database, *policy, held)
                            && unguarded.contains(&(command, label.as_str()))
                    })
                    .map(|(label, _)| label.as_str())
                    .collect();
                if reached.is_empty() {
                    continue;
                }
                for clause in applied(database, *policy, command)? {
                    if clause.stage != stage
                        || (clause.clause == PolicyClause::Using
                            && !is_literal_true(clause.expression))
                        || !is_tautology(database, table, clause.expression)?
                    {
                        continue;
                    }
                    commands.push(keyword);
                    writers.extend(reached.iter().copied());
                    let expression = clause.expression.to_string();
                    if !sites
                        .iter()
                        .any(|site| site.clause == clause.clause && site.expression == expression)
                    {
                        sites.push(PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new((*policy).clone()),
                            clause: clause.clause,
                            expression,
                        });
                    }
                }
            }
            if sites.is_empty() {
                continue;
            }
            let name = policy.name();
            let commands = commands.join(", ");
            let writers = writers.into_iter().collect::<Vec<_>>().join(", ");
            reporter.policies(
                sites,
                format!(
                    "Policy '{name}' on '{}' lets {writers} {commands} every row, since its clause is true whatever the row holds.",
                    table.table_name()
                ),
                format!(
                    "Make '{name}' compare the row to the caller, such as its owner or tenant column, or keep the write to a role no client holds. Allow a deliberate unconditional write with `allow_policy`."
                ),
            )?;
        }
        Ok(())
    }
}
