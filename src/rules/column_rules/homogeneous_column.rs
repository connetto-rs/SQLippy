//! Submodule providing the `HomogeneousColumn` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    traits::{
        CheckConstraintLike, ColumnLike, DatabaseLike, ForeignKeyLike, TableIndexLike, TableLike,
    },
};
use sqlparser::ast::{BinaryOperator, Expr, Value, Visitor};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::{CheckedRows, names_cast_column, names_column},
        grant_support::is_subscribed,
        key_support::{equality_keys, nullable_host_columns},
        literal_support::literal,
        null_support::may_hold_null,
        policy_support::conjuncts,
        walk_support::walk,
    },
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

rule_definition!(
    /// Struct defining a rule that reports a homogeneous column, one holding
    /// the same value on every row of its table, or that value and `NULL`.
    ///
    /// A column is homogeneous in three spellings.
    ///
    /// - Its default is a literal other than `NULL` and a top-level conjunct
    ///   `column = literal` of a validated check of its table holds it there,
    ///   in either operand order, compared through parentheses and casts. A
    ///   check added `NOT VALID` fixes nothing, since rows stored before it
    ///   may hold any value.
    /// - It is generated, stored or virtual, as a literal other than `NULL`
    ///   under parentheses, casts and a sign.
    /// - An enforced and validated foreign key pairs it with a homogeneous
    ///   column, transitively through chains of keys. The key must check
    ///   every row where the column holds a value, so it is `MATCH FULL` or
    ///   none of its other referencing columns may hold `NULL`, since
    ///   `MATCH SIMPLE` checks nothing on a row with a `NULL` in the key.
    ///
    /// A column that may hold `NULL` is reported as holding the value or
    /// `NULL`, a nullness its other columns state already.
    ///
    /// # The subtype discriminator copy
    ///
    /// One homogeneous column is left silent, the copy `d` of a supertype's
    /// discriminator `t` through which a subtype `S` keys itself to the rows
    /// of one kind in its supertype `T`, as in
    /// `FOREIGN KEY (id, kind) REFERENCES grantees (id, kind)` with `kind`
    /// generated as `'user'`. It is skipped only when all of these hold.
    ///
    /// - `d` cannot hold `NULL`, and exactly one foreign key of `S` holds it,
    ///   enforced and validated, whose referencing columns are the primary
    ///   key of `S` plus `d`.
    /// - That key references the primary key of `T` plus `t`, which `T`
    ///   declares unique without a predicate, and `t` is not homogeneous in
    ///   `T`.
    /// - `d` is in no key, index or index predicate of `S`, and every
    ///   conjunct of a check of `S` that names it fixes it to its value.
    ///
    /// Every other homogeneous column of `S` is still reported, one inside
    /// its primary key included.
    ///
    /// The copy exists because PostgreSQL offers no declarative way to say
    /// that a subtype row references a supertype row of one kind. A foreign
    /// key compares stored columns only, so it cannot hold a literal, and its
    /// referenced columns must be a non-deferrable unique or primary key
    /// constraint or a non-partial unique index, so it cannot target
    /// `UNIQUE (id) WHERE kind = 'user'`. PostgreSQL 18 refuses virtual
    /// generated columns in foreign keys and unique constraints, so the copy
    /// takes storage. The skip goes once PostgreSQL accepts one of these.
    ///
    /// - A foreign key over a virtual generated column, proposed in
    ///   [foreign key on virtual generated column](https://commitfest.postgresql.org/patch/5782/)
    ///   and withdrawn from the PostgreSQL 19 final commitfest on 2026-03-13.
    /// - `CREATE ASSERTION` from SQL-92, which states disjointness without
    ///   the copy. Its
    ///   [PostgreSQL implementation](https://commitfest.postgresql.org/patch/1604/)
    ///   was returned with feedback in 2019, and Oracle Database 26
    ///   implements assertions.
    ///
    /// The alternatives today are a constraint trigger, which no reader of
    /// declarations can follow, or one relationship table per subtype, which
    /// [`ParallelTables`](crate::prelude::ParallelTables) reports.
    ///
    /// Nor is a column of a table the deployment declares subscribed with
    /// [`Deployment::with_subscribed_table`](crate::deployment::Deployment::with_subscribed_table)
    /// reported, since it takes the shape of the publisher's, where the
    /// finding belongs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = HomogeneousColumn::default().into();
    /// let generated = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE entries (id INT PRIMARY KEY, kind TEXT GENERATED ALWAYS AS ('entry') STORED NOT NULL);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&generated).is_err());
    /// let subtype = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE grantees (id INT PRIMARY KEY, kind TEXT NOT NULL, UNIQUE (id, kind));
    ///      CREATE TABLE users (
    ///          id INT PRIMARY KEY,
    ///          kind TEXT GENERATED ALWAYS AS ('user') STORED NOT NULL,
    ///          FOREIGN KEY (id, kind) REFERENCES grantees (id, kind)
    ///      );",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&subtype).is_ok());
    /// ```
    HomogeneousColumn,
    register_column_rule,
    LintGroup::Pedantic,
    "A column holding one value on every row carries no information, so every row stores, and every key and index repeats, a value the schema already states.",
    Some("https://www.postgresql.org/docs/current/sql-createtable.html"),
    RuleExample {
        bad: "CREATE TABLE entries (id INT PRIMARY KEY, kind TEXT GENERATED ALWAYS AS ('entry') STORED NOT NULL);",
        good: "CREATE TABLE entries (id INT PRIMARY KEY);",
    },
    Basis::Declared
);

/// How a column comes to hold one value on every row.
enum Evidence<'db, C> {
    /// A literal default a validated check holds the column to.
    Fixed,
    /// A generation expression that is a literal.
    Generated,
    /// A foreign key pairing the column with this homogeneous column.
    Referenced(&'db C),
}

/// A column holding one value on every row it does not leave `NULL`.
struct Homogeneous<'db, C> {
    evidence: Evidence<'db, C>,
    /// The literal every row holds, written where the chain of keys starts.
    value: &'db Expr,
    /// Whether a row may hold `NULL` instead.
    nullable: bool,
}

/// Whether `conjunct` is `column = fixed` in either operand order, the
/// literal compared through parentheses and casts.
fn fixes(conjunct: &Expr, column: &str, fixed: &Value) -> bool {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = conjunct
    else {
        return false;
    };
    (names_cast_column(left, column) && literal(right) == Some(fixed))
        || (names_cast_column(right, column) && literal(left) == Some(fixed))
}

/// Whether a validated check of the table of `column` holds it to `fixed`.
fn held<DB: DatabaseLike>(
    database: &DB,
    column: &DB::Column,
    fixed: &Value,
) -> Result<bool, LookupError> {
    let stored = column.stored_column_name();
    for check in column.check_constraints(database)? {
        if CheckedRows::Stored.checked_by(database, check)?
            && conjuncts(check.expression(database))
                .into_iter()
                .any(|conjunct| fixes(conjunct, &stored, fixed))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `expression` names the column whose stored name is `column`
/// anywhere inside it.
fn mentions(expression: &Expr, column: &str) -> bool {
    struct Mention<'c>(&'c str);
    impl Visitor for Mention<'_> {
        type Break = ();
        fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
            if names_column(expression, self.0) {
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        }
    }
    walk(expression, &mut Mention(column)).is_break()
}

/// How `column` holds one value on every row, or `None` when nothing
/// declared fixes it. `visiting` holds the columns whose foreign keys the
/// walk is already following, so a cycle of keys ends.
fn homogeneous<'db, DB: DatabaseLike>(
    database: &'db DB,
    column: &'db DB::Column,
    visiting: &mut Vec<&'db DB::Column>,
) -> Result<Option<Homogeneous<'db, DB::Column>>, LookupError> {
    if let Some(value) = column.generated_constant() {
        return Ok(Some(Homogeneous {
            evidence: Evidence::Generated,
            value,
            nullable: false,
        }));
    }
    let nullable = may_hold_null(database, column)?;
    if let Some(default) = column.default_expression()
        && let Some(fixed) = literal(default).filter(|value| !matches!(value, Value::Null))
        && held(database, column, fixed)?
    {
        return Ok(Some(Homogeneous {
            evidence: Evidence::Fixed,
            value: default,
            nullable,
        }));
    }
    visiting.push(column);
    let found = referenced(database, column, nullable, visiting);
    visiting.pop();
    found
}

/// How `column` holds one value through an enforced and validated foreign
/// key checking every row where it holds a value, pairing it with a
/// homogeneous column.
fn referenced<'db, DB: DatabaseLike>(
    database: &'db DB,
    column: &'db DB::Column,
    nullable: bool,
    visiting: &mut Vec<&'db DB::Column>,
) -> Result<Option<Homogeneous<'db, DB::Column>>, LookupError> {
    for foreign_key in column.foreign_keys(database)? {
        if !foreign_key.is_enforced(database)
            || !foreign_key.is_validated(database)?
            || !(foreign_key.match_full(database)
                || nullable_host_columns(database, foreign_key)?
                    .into_iter()
                    .all(|host| host == column))
        {
            continue;
        }
        for (host, target) in foreign_key
            .host_columns(database)?
            .zip(foreign_key.referenced_columns(database)?)
        {
            if host != column || visiting.contains(&target) {
                continue;
            }
            if let Some(found) = homogeneous(database, target, visiting)? {
                return Ok(Some(Homogeneous {
                    evidence: Evidence::Referenced(target),
                    value: found.value,
                    nullable,
                }));
            }
        }
    }
    Ok(None)
}

/// Whether `index` keys on `column`, whose stored name is `stored`, in its
/// columns, its `INCLUDE` list or its predicate.
fn indexes<DB: DatabaseLike, I: TableIndexLike<DB = DB>>(
    database: &DB,
    index: &I,
    column: &DB::Column,
    stored: &str,
) -> Result<bool, LookupError> {
    Ok(index.columns(database)?.any(|key| key == column)
        || index.include_columns(database)?.any(|key| key == column)
        || index
            .predicate()
            .is_some_and(|predicate| mentions(predicate, stored)))
}

/// Whether `column`, holding `value` on every row and never `NULL`, is the
/// copy of a supertype's discriminator its table keys itself to the
/// supertype through, as [`HomogeneousColumn`] lays the pattern out.
fn discriminator_copy<'db, DB: DatabaseLike>(
    database: &'db DB,
    column: &'db DB::Column,
    value: &Expr,
) -> Result<bool, LookupError> {
    let table = column.table(database);
    let primary_key: Vec<_> = table.primary_key_columns(database)?.collect();
    if primary_key.is_empty() || primary_key.contains(&column) {
        return Ok(false);
    }
    let mut foreign_keys = column.foreign_keys(database)?;
    let (Some(foreign_key), None) = (foreign_keys.next(), foreign_keys.next()) else {
        return Ok(false);
    };
    if !foreign_key.is_enforced(database)
        || !foreign_key.is_validated(database)?
        || foreign_key.is_self_referential(database)?
    {
        return Ok(false);
    }
    let hosts: Vec<_> = foreign_key.host_columns(database)?.collect();
    let targets: Vec<_> = foreign_key.referenced_columns(database)?.collect();
    let Some(discriminator) = hosts
        .iter()
        .position(|host| *host == column)
        .and_then(|position| targets.get(position).copied())
    else {
        return Ok(false);
    };
    if hosts.len() != primary_key.len() + 1
        || hosts
            .iter()
            .any(|host| *host != column && !primary_key.contains(host))
    {
        return Ok(false);
    }
    let supertype = foreign_key.referenced_table(database)?;
    let supertype_key: Vec<_> = supertype.primary_key_columns(database)?.collect();
    if targets.len() != supertype_key.len() + 1
        || supertype_key.contains(&discriminator)
        || targets
            .iter()
            .any(|target| *target != discriminator && !supertype_key.contains(target))
    {
        return Ok(false);
    }
    if !equality_keys(database, supertype)?
        .iter()
        .any(|key| key.len() == targets.len() && key.iter().all(|key| targets.contains(key)))
    {
        return Ok(false);
    }
    if homogeneous(database, discriminator, &mut Vec::new())?.is_some() {
        return Ok(false);
    }
    let stored = column.stored_column_name();
    let fixed = literal(value);
    for check in table.check_constraints(database)? {
        for conjunct in conjuncts(check.expression(database)) {
            if mentions(conjunct, &stored)
                && !fixed.is_some_and(|fixed| fixes(conjunct, &stored, fixed))
            {
                return Ok(false);
            }
        }
    }
    for index in table.unique_indices(database)? {
        if indexes(database, index, column, &stored)? {
            return Ok(false);
        }
    }
    for index in table.indices(database)? {
        if indexes(database, index, column, &stored)? {
            return Ok(false);
        }
    }
    for index in table.exclusion_indices(database)? {
        if indexes(database, index, column, &stored)? {
            return Ok(false);
        }
    }
    Ok(true)
}

impl<DB: DatabaseLike> ColumnRule for HomogeneousColumn<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let table = column.table(database);
        if is_subscribed(database, reporter.deployment(), table) {
            return Ok(());
        }
        let Some(found) = homogeneous(database, column, &mut Vec::new())? else {
            return Ok(());
        };
        if !found.nullable && discriminator_copy(database, column, found.value)? {
            return Ok(());
        }
        let name = format!("{}.{}", table.table_name(), column.column_name());
        let value = found.value;
        let held = if found.nullable {
            "every row holds that value or NULL"
        } else {
            "every row holds that same value"
        };
        let (message, resolution) = match found.evidence {
            Evidence::Fixed => (
                format!("Column '{name}' defaults to {value} and a check holds it there, so {held}."),
                "Drop the column with its default and its check, and key any reference that carries it by the columns that vary.".to_owned(),
            ),
            Evidence::Generated => (
                format!("Column '{name}' is generated as {value}, so {held}."),
                "Drop the column, and key any reference that carries it by the columns that vary.".to_owned(),
            ),
            Evidence::Referenced(target) => {
                let target = format!(
                    "{}.{}",
                    target.table(database).table_name(),
                    target.column_name()
                );
                (
                    format!(
                        "Column '{name}' references '{target}', which holds {value} on every row, so {held}."
                    ),
                    format!(
                        "Drop '{target}' or take it out of the key this column references, then drop the column from its foreign key and its table."
                    ),
                )
            }
        };
        reporter.column(column, message, resolution)?;
        Ok(())
    }
}
