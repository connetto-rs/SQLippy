//! Submodule providing the `ClientChosenTimestamp` rule.

use std::{borrow::Cow, ops::ControlFlow, time::Duration};

use sql_traits::{
    errors::LookupError,
    structs::TriggerEnablement,
    traits::{CheckConstraintLike, ColumnLike, DatabaseLike, FunctionLike, TableLike, TriggerLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{
    BinaryOperator, Expr, Ident, ObjectName, TriggerEvent, TriggerObject, TriggerObjectKind,
    TriggerPeriod, UnaryOperator, Visitor,
};
use sqlparser_plpgsql::{
    embedded::{self, AliasTarget, Block, DeclarationKind, Node, RaiseLevel, Target},
    embedded_sql,
};

use super::{flag_not_boolean, moment_stored_as_text};
use crate::{
    deployment::Deployment,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        clock_support::{bound_clock, is_clock, upper_bound},
        closed_set_support::names_column,
        expression_site_support::is_null_literal,
        policy_support::is_column_reference,
        walk_support::walk,
    },
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// Struct defining a rule that reports a time-related column a client role
/// may write when neither a trigger stamps it from the database's clock nor a
/// check bounds it by that clock, so a client chooses when its event happened.
///
/// A column whose name ends with `_at` is time-related, apart from names of
/// future instants such as `expires_at`. A client role is one the deployment
/// declares, or any role while it declares none. It may write the column when
/// the source does not prove that it lacks `INSERT` or `UPDATE` on it, by a
/// table or column privilege held directly, through `PUBLIC` or through a
/// role it inherits from. A default such as `DEFAULT now()` stamps nothing,
/// since a client writing the column replaces it.
///
/// A `BEFORE` row trigger firing on the command in `origin` sessions, as one
/// left enabled or set `ENABLE ALWAYS` does, stamps the column when every
/// path through its PL/pgSQL function that returns `NEW` either last assigns
/// the column from a clock call reading no column or variable, `OLD`'s value
/// or `NULL`, or follows a branch on the column `IS NULL` that leaves it
/// null. A path returning `NULL` or raising an exception writes no row. A
/// function with a loop, an exception handler, an `EXIT`, a `RETURN` of
/// anything else or a write to the whole `NEW` record stamps nothing. A
/// trigger fires on `UPDATE` when its event names no column or names this
/// one. A `WHEN` condition keeps it stamping only when every row it skips
/// leaves the column null, or, for a trigger firing on `UPDATE` alone, when
/// it skips only rows whose column `IS NOT DISTINCT FROM` its `OLD` value.
///
/// A check bounds the column when a top-level `AND` conjunct bounds the plain
/// column from above by the current time, optionally plus a constant
/// tolerance. It is the fix for an event only the client observes, such as a
/// time a device records offline and syncs later, where a database stamp
/// would record the upload. The resolution adds the tolerance the deployment
/// declares with
/// [`Deployment::with_clock_tolerance`](crate::deployment::Deployment::with_clock_tolerance).
///
/// A column [`MomentStoredAsText`](crate::rules::MomentStoredAsText) or
/// [`FlagNotBoolean`](crate::rules::FlagNotBoolean) reports is left to that
/// rule, since its type comes first.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = ClientChosenTimestamp::default().into();
/// constrainer.set_deployment(Deployment::default().with_app_role("app"));
/// let schema = "CREATE ROLE app;
///     CREATE TABLE resources (id INT PRIMARY KEY, archived_at TIMESTAMPTZ);
///     GRANT UPDATE (archived_at) ON resources TO app;";
///
/// let chosen = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&chosen).is_err());
///
/// let stamped = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema}
///      CREATE FUNCTION stamp() RETURNS trigger LANGUAGE plpgsql AS $$
///      BEGIN NEW.archived_at := now(); RETURN NEW; END $$;
///      CREATE TRIGGER stamp BEFORE INSERT OR UPDATE OF archived_at ON resources
///      FOR EACH ROW EXECUTE FUNCTION stamp();"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&stamped).is_ok());
///
/// let bounded = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema}
///      ALTER TABLE resources ADD CHECK (archived_at <= now() + interval '5 minutes');"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&bounded).is_ok());
/// ```
pub struct ClientChosenTimestamp<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ClientChosenTimestamp<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ClientChosenTimestamp<DB>> for GenericConstrainer<DB> {
    fn from(rule: ClientChosenTimestamp<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ClientChosenTimestamp<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(ClientChosenTimestamp),
            group: LintGroup::Pedantic,
            rationale: "A timestamp recording when something happened holds the instant a client writes, so a client can backdate the event, unless the database stamps it from its own clock or, for an event only the client observes, bounds it by that clock.",
            source: None,
            basis: Basis::Names,
            example: RuleExample {
                bad: "CREATE TABLE users (id INT PRIMARY KEY, created_at TIMESTAMPTZ DEFAULT now());",
                good: "CREATE TABLE users (id INT PRIMARY KEY, created_at TIMESTAMPTZ);
CREATE FUNCTION stamp_created_at() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.created_at := now(); RETURN NEW; END $$;
CREATE TRIGGER stamp_created_at BEFORE INSERT OR UPDATE OF created_at ON users FOR EACH ROW EXECUTE FUNCTION stamp_created_at();",
            },
        };
        &METADATA
    }
}

/// The PostgreSQL interval text measuring `tolerance` whole, in minutes,
/// seconds, milliseconds or microseconds, or `None` for no tolerance.
fn interval_text(tolerance: Duration) -> Option<String> {
    let micros = tolerance.as_micros();
    let (count, unit) = match micros {
        0 => return None,
        _ if micros.is_multiple_of(60_000_000) => (micros / 60_000_000, "minute"),
        _ if micros.is_multiple_of(1_000_000) => (micros / 1_000_000, "second"),
        _ if micros.is_multiple_of(1_000) => (micros / 1_000, "millisecond"),
        _ => (micros, "microsecond"),
    };
    let plural = if count == 1 { "" } else { "s" };
    Some(format!("{count} {unit}{plural}"))
}

/// Whether a top-level `AND` conjunct of the check bounds the column from
/// above by the current time.
fn keeps_in_past(expression: &Expr, column: &str) -> bool {
    match expression {
        Expr::Nested(inner) => keeps_in_past(inner, column),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => keeps_in_past(left, column) || keeps_in_past(right, column),
        _ => upper_bound(expression).is_some_and(|(value, bound)| {
            names_column(value, column) && bound_clock(bound).is_some()
        }),
    }
}

/// The commands that write a column, in the order messages name them.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Writes {
    insert: bool,
    update: bool,
}

impl Writes {
    const BOTH: Self = Self {
        insert: true,
        update: true,
    };

    /// The commands written in `self` and not in `stamped`.
    fn without(self, stamped: Self) -> Self {
        Self {
            insert: self.insert && !stamped.insert,
            update: self.update && !stamped.update,
        }
    }

    /// The commands joined with `separator`, `UPDATE` followed by `suffix`.
    fn join(self, separator: &str, suffix: &str) -> String {
        let update = format!("UPDATE{suffix}");
        [
            self.insert.then_some("INSERT"),
            self.update.then_some(update.as_str()),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(separator)
    }
}

/// The commands a client role may write `column` of `table` with.
fn client_writes<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    table: &DB::Table,
    column: &DB::Column,
) -> Result<Writes, LookupError> {
    let mut writes = Writes::default();
    let mut declared = false;
    for name in deployment.app_roles().chain(deployment.anonymous_roles()) {
        declared = true;
        let Some(role) = database.role(name) else {
            return Ok(Writes::BOTH);
        };
        let possible = table.possible_privileges(role, database)?;
        writes.insert |= possible.insert.on_column(column);
        writes.update |= possible.update.on_column(column);
    }
    Ok(if declared { writes } else { Writes::BOTH })
}

/// The stored name of each part of `name`.
fn stored_parts(name: &ObjectName) -> Option<Vec<Cow<'_, str>>> {
    name.0
        .iter()
        .map(|part| part.as_ident().map(stored))
        .collect()
}

/// Whether the expression, under parentheses, names `record` alone.
fn names_record(expression: &Expr, record: &str) -> bool {
    match expression {
        Expr::Nested(inner) => names_record(inner, record),
        Expr::Identifier(ident) => stored(ident) == record,
        _ => false,
    }
}

/// Whether the expression, under parentheses and casts, is `record.column`.
fn names_field(expression: &Expr, record: &str, column: &str) -> bool {
    match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => names_field(inner, record, column),
        Expr::CompoundIdentifier(parts) => {
            matches!(parts.as_slice(), [first, second] if stored(first) == record && stored(second) == column)
        }
        _ => false,
    }
}

/// The name PostgreSQL stores for `ident`.
fn stored(ident: &Ident) -> Cow<'_, str> {
    normalize_identifier(&ident.value, ident.quote_style.is_some())
}

/// Whether `expression` being true, or not being true when `holds` is false,
/// leaves `NEW.column` null.
fn leaves_null(expression: &Expr, column: &str, holds: bool) -> bool {
    match expression {
        Expr::Nested(inner) => leaves_null(inner, column, holds),
        Expr::IsNull(tested) => holds && names_field(tested, "new", column),
        Expr::IsNotNull(tested) => !holds && names_field(tested, "new", column),
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => {
            let mut negated = expr.as_ref();
            while let Expr::Nested(inner) = negated {
                negated = inner;
            }
            matches!(negated, Expr::IsNull(_) | Expr::IsNotNull(_))
                && leaves_null(negated, column, !holds)
        }
        Expr::BinaryOp { left, op, right } => {
            let joins = if holds {
                BinaryOperator::And
            } else {
                BinaryOperator::Or
            };
            *op == joins && (leaves_null(left, column, holds) || leaves_null(right, column, holds))
        }
        _ => false,
    }
}

/// Whether every row a trigger's `WHEN` condition skips leaves `NEW.column`
/// null, or, for a trigger firing on `UPDATE` alone, keeps its stored value.
fn skips_no_chosen_value(condition: &Expr, column: &str, update_only: bool) -> bool {
    let keeps_stored = |left: &Expr, right: &Expr| {
        update_only
            && (names_field(left, "new", column) && names_field(right, "old", column)
                || names_field(left, "old", column) && names_field(right, "new", column))
    };
    match condition {
        Expr::Nested(inner) => skips_no_chosen_value(inner, column, update_only),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => {
            skips_no_chosen_value(left, column, update_only)
                || skips_no_chosen_value(right, column, update_only)
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            skips_no_chosen_value(left, column, update_only)
                && skips_no_chosen_value(right, column, update_only)
        }
        Expr::IsDistinctFrom(left, right) => keeps_stored(left, right),
        _ => leaves_null(condition, column, false),
    }
}

/// Whether the expression calls a clock and reads no column or variable.
fn reads_only_the_clock(expression: &Expr) -> bool {
    struct Reads {
        clock: bool,
    }
    impl Visitor for Reads {
        type Break = ();
        fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
            if is_column_reference(expression) || matches!(expression, Expr::Subquery(_)) {
                return ControlFlow::Break(());
            }
            self.clock |= is_clock(expression);
            ControlFlow::Continue(())
        }
    }
    let mut reads = Reads { clock: false };
    walk(expression, &mut reads).is_continue() && reads.clock
}

/// Which values `NEW.column` may hold on the paths reaching a step.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Reach {
    /// Some path reaches it with a value the client may have chosen.
    chosen: bool,
    /// Some path reaches it with a stamped or null value.
    stamped: bool,
}

impl Reach {
    const NONE: Self = Self {
        chosen: false,
        stamped: false,
    };

    fn union(self, other: Self) -> Self {
        Self {
            chosen: self.chosen || other.chosen,
            stamped: self.stamped || other.stamped,
        }
    }

    /// The paths among these on which `condition` is true, or not true when
    /// `holds` is false.
    fn when(self, condition: &Expr, column: &str, holds: bool) -> Self {
        if self != Self::NONE && leaves_null(condition, column, holds) {
            Self {
                chosen: false,
                stamped: true,
            }
        } else {
            self
        }
    }
}

/// Follows a trigger function's paths to the values of `NEW.column` it
/// returns, `None` once a path returns a value the client chose or takes
/// control flow it cannot follow.
struct Stamping<'c> {
    column: &'c str,
}

/// What a write to a target does to `NEW.column`.
enum Written {
    /// It leaves the column alone.
    Elsewhere,
    /// It assigns the column itself.
    Column,
    /// It writes the column in a way the analysis does not follow.
    Unfollowed,
}

impl Stamping<'_> {
    fn target(&self, target: &Target) -> Written {
        let Some(parts) = stored_parts(&target.name) else {
            return Written::Unfollowed;
        };
        match parts.as_slice() {
            [record, column] if record == "new" && column == self.column => {
                if target.indirection.is_empty() {
                    Written::Column
                } else {
                    Written::Unfollowed
                }
            }
            [record] if record == "new" => Written::Unfollowed,
            [record, column, ..] if record == "new" && column == self.column => Written::Unfollowed,
            parts if parts.iter().skip(1).any(|part| part == "new") => Written::Unfollowed,
            _ => Written::Elsewhere,
        }
    }

    /// Whether the targets leave the column alone.
    fn spares<'t>(&self, targets: impl IntoIterator<Item = &'t Target>) -> bool {
        targets
            .into_iter()
            .all(|target| matches!(self.target(target), Written::Elsewhere))
    }

    /// Whether the assigned value is stamped by the database.
    fn stamps(&self, value: &Expr) -> bool {
        is_null_literal(value)
            || names_field(value, "old", self.column)
            || reads_only_the_clock(value)
    }

    fn block(&self, block: &Block, reach: Reach) -> Option<Reach> {
        let shadows = block.declarations.iter().any(|declaration| {
            declaration.name == "new"
                || matches!(&declaration.kind, DeclarationKind::Alias(AliasTarget::Name(name))
                    if stored_parts(name).is_none_or(|parts| parts.iter().any(|part| part == "new")))
        });
        if shadows || !block.handlers.is_empty() {
            return None;
        }
        self.nodes(&block.statements, reach)
    }

    fn nodes(&self, nodes: &[Node], mut reach: Reach) -> Option<Reach> {
        for node in nodes {
            reach = self.node(node, reach)?;
        }
        Some(reach)
    }

    fn node(&self, node: &Node, reach: Reach) -> Option<Reach> {
        match node {
            Node::Assignment(assignment) => match self.target(&assignment.target) {
                Written::Elsewhere => Some(reach),
                Written::Unfollowed => None,
                Written::Column if reach == Reach::NONE => Some(reach),
                Written::Column => {
                    let stamped = self.stamps(&embedded::expression(&assignment.value));
                    Some(Reach {
                        chosen: !stamped,
                        stamped,
                    })
                }
            },
            Node::Statement { into, .. } | Node::Dynamic { into, .. } => into
                .as_ref()
                .is_none_or(|into| self.spares(&into.targets))
                .then_some(reach),
            Node::Fetch(fetch) => self.spares(&fetch.targets).then_some(reach),
            Node::Diagnostics(diagnostics) => self
                .spares(diagnostics.items.iter().map(|item| &item.target))
                .then_some(reach),
            Node::Open(_)
            | Node::Perform { .. }
            | Node::Move { .. }
            | Node::Close { .. }
            | Node::Assert(_) => Some(reach),
            Node::Raise(raise) => Some(if raise.level == RaiseLevel::Exception {
                Reach::NONE
            } else {
                reach
            }),
            Node::Block(block) => self.block(block, reach),
            Node::If(conditional) => self.branches(
                conditional
                    .branches
                    .iter()
                    .map(|branch| (Some(&branch.condition), branch.statements.as_slice())),
                &conditional.otherwise,
                reach,
            ),
            Node::Case(case) => self.branches(
                case.branches.iter().map(|branch| {
                    (
                        case.subject.is_none().then_some(&branch.condition),
                        branch.statements.as_slice(),
                    )
                }),
                &case.otherwise,
                reach,
            ),
            Node::Return { value: Some(value) } => {
                let value = embedded::expression(value);
                if is_null_literal(&value) || (names_record(&value, "new") && !reach.chosen) {
                    Some(Reach::NONE)
                } else {
                    None
                }
            }
            Node::Return { value: None }
            | Node::ReturnNext { .. }
            | Node::ReturnQuery(_)
            | Node::Loop(_)
            | Node::Exit(_)
            | Node::Commit { .. }
            | Node::Rollback { .. } => None,
        }
    }

    /// The paths through branches tried in order, each run where its
    /// condition, when one is known, is true and every earlier one is not.
    fn branches<'n>(
        &self,
        branches: impl Iterator<Item = (Option<&'n Box<sqlparser::ast::Query>>, &'n [Node])>,
        otherwise: &[Node],
        mut reach: Reach,
    ) -> Option<Reach> {
        let mut out = Reach::NONE;
        for (condition, statements) in branches {
            let condition = condition.map(|condition| embedded::expression(condition));
            let taken = condition
                .as_deref()
                .map_or(reach, |condition| reach.when(condition, self.column, true));
            out = out.union(self.nodes(statements, taken)?);
            if let Some(condition) = condition.as_deref() {
                reach = reach.when(condition, self.column, false);
            }
        }
        Some(out.union(self.nodes(otherwise, reach)?))
    }
}

/// Whether every path through `function` returning `NEW` leaves `column`
/// stamped by the database, for the rows on which `condition` holds.
fn function_stamps<F: FunctionLike>(function: &F, column: &str, condition: Option<&Expr>) -> bool {
    if function.stored_language().as_deref() != Some("plpgsql") {
        return false;
    }
    let Some(block) = function.body().and_then(|body| embedded_sql(body).ok()) else {
        return false;
    };
    let fired = Reach {
        chosen: true,
        stamped: false,
    };
    let entry = condition.map_or(fired, |condition| fired.when(condition, column, true));
    Stamping { column }.block(&block, entry).is_some()
}

/// The commands a `BEFORE` row trigger on the column's table stamps it on,
/// counting only triggers that fire in the `origin` sessions clients write in.
fn stamped_writes<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    column: &str,
) -> Result<Writes, LookupError> {
    let mut stamped = Writes::default();
    for trigger in table.triggers(database)? {
        let per_row = matches!(
            trigger.orientation(),
            Some(
                TriggerObjectKind::For(TriggerObject::Row)
                    | TriggerObjectKind::ForEach(TriggerObject::Row)
            )
        );
        let condition = trigger.condition();
        let update_only = !trigger.events().contains(&TriggerEvent::Insert);
        if trigger.timing() != Some(TriggerPeriod::Before)
            || !matches!(
                trigger.enablement(database)?,
                TriggerEnablement::Origin | TriggerEnablement::Always
            )
            || !per_row
            || condition
                .is_some_and(|condition| !skips_no_chosen_value(condition, column, update_only))
            || !trigger
                .function(database)
                .is_some_and(|function| function_stamps(function, column, condition))
        {
            continue;
        }
        for event in trigger.events() {
            match event {
                TriggerEvent::Insert => stamped.insert = true,
                TriggerEvent::Update(columns) => {
                    stamped.update |=
                        columns.is_empty() || columns.iter().any(|named| stored(named) == column);
                }
                TriggerEvent::Delete | TriggerEvent::Truncate => {}
            }
        }
    }
    Ok(stamped)
}

impl<DB: DatabaseLike> ColumnRule for ClientChosenTimestamp<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let column_name = column.column_name();

        // Identify time-related columns by suffix "_at".
        if !column_name.ends_with("_at") {
            return Ok(());
        }

        // Exclude common future or interval boundary columns.
        let future_or_ambiguous = [
            "expires_at",
            "due_at",
            "starts_at",
            "ends_at",
            "scheduled_at",
        ];
        let vocabularies = reporter.deployment().vocabularies();
        if future_or_ambiguous.contains(&column_name)
            || moment_stored_as_text::HINT.matches(database, column, vocabularies)
            || flag_not_boolean::HINT.matches(database, column, vocabularies)
        {
            return Ok(());
        }
        if column
            .check_constraints(database)?
            .any(|check| keeps_in_past(check.expression(database), column_name))
        {
            return Ok(());
        }

        let table = column.table(database);
        let written = client_writes(database, reporter.deployment(), table, column)?;
        if written == Writes::default() {
            return Ok(());
        }
        let unstamped = written.without(stamped_writes(database, table, column_name)?);
        if unstamped == Writes::default() {
            return Ok(());
        }

        let table_name = table.table_name();
        let check = match reporter
            .deployment()
            .clock_tolerance()
            .and_then(interval_text)
        {
            Some(tolerance) => format!(
                "add `CHECK ({column_name} <= now() + interval '{tolerance}')`, the deployment's clock tolerance"
            ),
            None => format!(
                "add `CHECK ({column_name} <= now())`, adding the tolerance declared with `Deployment::with_clock_tolerance` when the clocks stamping rows can run ahead"
            ),
        };
        reporter.column(
            column,
            format!(
                "Time-related column '{table_name}.{column_name}' holds the instant a client role writes with {}, and neither the database's clock stamps it nor a check bounds it by that clock.",
                unstamped.join(" and ", "")
            ),
            format!(
                "When the database observes the event, stamp it in a `BEFORE {} ON {table_name} FOR EACH ROW` trigger that assigns `NEW.{column_name} := now()` on every path keeping it set, or revoke the write from the client roles and stamp it in a `SECURITY DEFINER` function. When only the client observes it, such as a time recorded offline and synced later, {check}.",
                unstamped.join(" OR ", &format!(" OF {column_name}"))
            ),
        )?;
        Ok(())
    }
}
