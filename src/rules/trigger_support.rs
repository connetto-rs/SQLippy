//! Facts about triggers and the functions they run, shared by the trigger
//! rules.

use std::borrow::Cow;

use sql_traits::{
    errors::LookupError,
    structs::TriggerEnablement,
    traits::{DatabaseLike, FunctionLike, TriggerLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::{
    ast::{
        Delete, Expr, FromTable, Ident, Insert, Merge, ObjectName, ObjectNamePart, Query,
        SelectItem, Statement, TableFactor, TableObject, TableWithJoins, TriggerEvent,
        TriggerObject, TriggerObjectKind, TriggerPeriod, Update,
    },
    keywords::Keyword,
    tokenizer::Token,
};
use sqlparser_plpgsql::embedded::{AliasTarget, Block, DeclarationKind, Target};

use crate::rules::{cte_support::stored_table, function_reach_support::Sought};

/// The name PostgreSQL stores for `ident`.
pub(crate) fn stored(ident: &Ident) -> Cow<'_, str> {
    normalize_identifier(&ident.value, ident.quote_style.is_some())
}

/// The stored name of each part of `name`, which the PL/pgSQL parser builds
/// from identifiers alone.
pub(crate) fn stored_parts(name: &ObjectName) -> Vec<Cow<'_, str>> {
    name.0
        .iter()
        .filter_map(ObjectNamePart::as_ident)
        .map(stored)
        .collect()
}

/// Whether the expression, under parentheses, names `record` alone.
pub(crate) fn names_record(expression: &Expr, record: &str) -> bool {
    match expression {
        Expr::Nested(inner) => names_record(inner, record),
        Expr::Identifier(ident) => stored(ident) == record,
        _ => false,
    }
}

/// The stored name of the field of `NEW` the expression, under parentheses,
/// names.
pub(crate) fn new_field(expression: &Expr) -> Option<Cow<'_, str>> {
    match expression {
        Expr::Nested(inner) => new_field(inner),
        Expr::CompoundIdentifier(parts) => match parts.as_slice() {
            [record, field] if stored(record) == "new" => Some(stored(field)),
            _ => None,
        },
        _ => None,
    }
}

/// Whether `expression`, under parentheses, is `NEW.column`.
pub(crate) fn names_new_field(expression: &Expr, column: &str) -> bool {
    new_field(expression).is_some_and(|field| field == column)
}

/// What a write to a PL/pgSQL target does to `NEW.column`.
pub(crate) enum Written {
    /// It leaves the column alone.
    Elsewhere,
    /// It assigns the column itself.
    Column,
    /// It writes the column in a way the analysis does not follow.
    Unfollowed,
}

/// What writing `target` does to `NEW.column`.
pub(crate) fn new_field_write(target: &Target, column: &str) -> Written {
    let parts = stored_parts(&target.name);
    match parts.as_slice() {
        [record, named] if record == "new" && named == column => {
            if target.indirection.is_empty() {
                Written::Column
            } else {
                Written::Unfollowed
            }
        }
        [record] if record == "new" => Written::Unfollowed,
        [record, named, ..] if record == "new" && named == column => Written::Unfollowed,
        parts if parts.iter().skip(1).any(|part| part == "new") => Written::Unfollowed,
        _ => Written::Elsewhere,
    }
}

/// Whether `block` declares a variable or an alias that hides the trigger's
/// `NEW` row.
pub(crate) fn shadows_new(block: &Block) -> bool {
    block.declarations.iter().any(|declaration| {
        declaration.name == "new"
            || matches!(&declaration.kind, DeclarationKind::Alias(AliasTarget::Name(name))
                if stored_parts(name).iter().any(|part| part == "new"))
    })
}

/// The trigger row an identifier names, `Some(true)` for `NEW` and
/// `Some(false)` for `OLD`, a quoted name matching only in lower case.
pub(crate) fn row(ident: &Ident) -> Option<bool> {
    let names = |row: &str| {
        if ident.quote_style.is_some() {
            ident.value == row
        } else {
            ident.value.eq_ignore_ascii_case(row)
        }
    };
    if names("new") {
        Some(true)
    } else if names("old") {
        Some(false)
    } else {
        None
    }
}

/// Whether `trigger` fires on `UPDATE`.
pub(crate) fn fires_on_update<T: TriggerLike>(trigger: &T) -> bool {
    trigger
        .events()
        .iter()
        .any(|event| matches!(event, TriggerEvent::Update(_)))
}

/// Whether `trigger` fires once per row at `timing`.
pub(crate) fn row_trigger<T: TriggerLike>(trigger: &T, timing: TriggerPeriod) -> bool {
    trigger.timing() == Some(timing)
        && matches!(
            trigger.orientation(),
            Some(
                TriggerObjectKind::ForEach(TriggerObject::Row)
                    | TriggerObjectKind::For(TriggerObject::Row)
            )
        )
}

/// Whether `trigger` fires on `INSERT`.
pub(crate) fn fires_on_insert<T: TriggerLike>(trigger: &T) -> bool {
    trigger
        .events()
        .iter()
        .any(|event| matches!(event, TriggerEvent::Insert))
}

/// The expression a PL/pgSQL expression evaluates, read as the `SELECT` of
/// one expression PostgreSQL runs it as.
pub(crate) fn evaluated(query: &Query) -> Option<&Expr> {
    let select = query.body.as_select()?;
    match select.projection.as_slice() {
        [SelectItem::UnnamedExpr(expression)] if select.from.is_empty() => Some(expression),
        _ => None,
    }
}

/// Every trigger, with the function it runs.
pub(crate) fn triggers_with_functions<DB: DatabaseLike>(
    database: &DB,
) -> impl Iterator<Item = (&DB::Function, &DB::Trigger)> {
    database.functions().flat_map(move |function| {
        function
            .triggers(database)
            .map(move |trigger| (function, trigger))
    })
}

/// Whether `trigger` fires in the sessions client roles write in.
pub(crate) fn fires_for_clients<DB: DatabaseLike>(
    database: &DB,
    trigger: &DB::Trigger,
) -> Result<bool, LookupError> {
    Ok(matches!(
        trigger.enablement(database)?,
        TriggerEnablement::Origin | TriggerEnablement::Always
    ))
}

/// Whether a table that a statement's `INSERT`, `UPDATE`, `DELETE` or
/// `MERGE` names passes `test`.
fn writes_table_where(statement: &Statement, mut test: impl FnMut(&ObjectName) -> bool) -> bool {
    match statement {
        Statement::Insert(Insert {
            table: TableObject::TableName(name),
            ..
        })
        | Statement::Update(Update {
            table:
                TableWithJoins {
                    relation: TableFactor::Table { name, .. },
                    ..
                },
            ..
        })
        | Statement::Merge(Merge {
            table: TableFactor::Table { name, .. },
            ..
        }) => test(name),
        Statement::Delete(Delete {
            from: FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables),
            ..
        }) => tables
            .iter()
            .any(|table| matches!(&table.relation, TableFactor::Table { name, .. } if test(name))),
        _ => false,
    }
}

/// Whether the body tokens starting at `at` write a table, holding `INSERT
/// INTO`, `DELETE FROM`, `MERGE INTO` or an `UPDATE` that is no row lock or
/// conflict action.
fn writes_at(tokens: &[&Token], at: usize) -> Option<bool> {
    let Some(Token::Word(word)) = tokens.get(at) else {
        return None;
    };
    let next = |keyword: Keyword| matches!(tokens.get(at + 1), Some(Token::Word(next)) if next.keyword == keyword);
    let writes = match word.keyword {
        Keyword::INSERT | Keyword::MERGE => next(Keyword::INTO),
        Keyword::DELETE => next(Keyword::FROM),
        Keyword::UPDATE => !matches!(
            at.checked_sub(1).map(|before| tokens[before]),
            Some(Token::Word(before)) if matches!(
                before.keyword,
                Keyword::FOR | Keyword::DO | Keyword::KEY | Keyword::ON
                    | Keyword::OR | Keyword::BEFORE | Keyword::AFTER
            )
        ),
        _ => false,
    };
    writes.then_some(true)
}

/// Writes to any table but one, directly or through the functions a body
/// calls.
pub(crate) struct WritesElsewhere<'db, DB: DatabaseLike> {
    database: &'db DB,
    table: &'db DB::Table,
}

impl<'db, DB: DatabaseLike> WritesElsewhere<'db, DB> {
    /// Looks for writes to tables other than `table`.
    pub(crate) const fn new(database: &'db DB, table: &'db DB::Table) -> Self {
        Self { database, table }
    }
}

impl<DB: DatabaseLike> Sought for WritesElsewhere<'_, DB> {
    type Found = ();

    fn expression(&self, _expression: &Expr) -> Option<()> {
        None
    }

    /// A statement writes the table its `INSERT`, `UPDATE`, `DELETE` or
    /// `MERGE` names.
    fn statement(&self, statement: &Statement) -> Option<()> {
        writes_table_where(statement, |name| {
            !matches!(
                stored_table(self.database, name, None),
                Ok(Some(table)) if table == self.table
            )
        })
        .then_some(())
    }

    /// A called body writes when it holds `INSERT INTO`, `DELETE FROM`,
    /// `MERGE INTO` or an `UPDATE` that is no row lock or conflict action.
    fn tokens(&self, tokens: &[&Token], at: usize) -> Option<bool> {
        writes_at(tokens, at)
    }

    fn call(&self) {}
}

/// Writes that may reach one table, directly or through the functions a body
/// calls. A called body is taken to write it whenever it writes any table.
pub(crate) struct WritesTable<'db, DB: DatabaseLike> {
    database: &'db DB,
    table: &'db DB::Table,
}

impl<'db, DB: DatabaseLike> WritesTable<'db, DB> {
    /// Looks for writes that may reach `table`.
    pub(crate) const fn new(database: &'db DB, table: &'db DB::Table) -> Self {
        Self { database, table }
    }
}

impl<DB: DatabaseLike> Sought for WritesTable<'_, DB> {
    type Found = ();

    fn expression(&self, _expression: &Expr) -> Option<()> {
        None
    }

    /// A statement writes the table when its `INSERT`, `UPDATE`, `DELETE` or
    /// `MERGE` names it or a name that does not resolve.
    fn statement(&self, statement: &Statement) -> Option<()> {
        writes_table_where(statement, |name| {
            !matches!(
                stored_table(self.database, name, None),
                Ok(Some(table)) if table != self.table
            )
        })
        .then_some(())
    }

    fn tokens(&self, tokens: &[&Token], at: usize) -> Option<bool> {
        writes_at(tokens, at)
    }

    fn call(&self) {}
}
