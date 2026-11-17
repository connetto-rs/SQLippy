//! Facts about triggers and the functions they run, shared by the trigger
//! rules.

use sql_traits::traits::{DatabaseLike, TriggerLike};
use sqlparser::{
    ast::{
        Expr, FromTable, Ident, ObjectName, Query, SelectItem, SetExpr, Statement, TableFactor,
        TableObject, TableWithJoins, TriggerEvent, TriggerObject, TriggerObjectKind, TriggerPeriod,
    },
    keywords::Keyword,
    tokenizer::Token,
};

use crate::rules::{cte_support::stored_table, function_reach_support::Sought};

/// The trigger row an identifier names, `Some(true)` for `NEW` and
/// `Some(false)` for `OLD`.
pub(crate) fn row(ident: &Ident) -> Option<bool> {
    if ident.quote_style.is_some() {
        return None;
    }
    if ident.value.eq_ignore_ascii_case("new") {
        Some(true)
    } else if ident.value.eq_ignore_ascii_case("old") {
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
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    match select.projection.as_slice() {
        [SelectItem::UnnamedExpr(expression)] if select.from.is_empty() => Some(expression),
        _ => None,
    }
}

/// The name of a plain table reference.
const fn factor_name(factor: &TableFactor) -> Option<&ObjectName> {
    match factor {
        TableFactor::Table { name, .. } => Some(name),
        _ => None,
    }
}

/// The tables a statement writes, by the names it writes them under, or
/// `None` for a statement that writes nothing.
fn written_names(statement: &Statement) -> Option<Vec<&ObjectName>> {
    Some(match statement {
        Statement::Insert(insert) => match &insert.table {
            TableObject::TableName(name) => vec![name],
            TableObject::TableFunction(_) | TableObject::TableQuery(_) => Vec::new(),
        },
        Statement::Update(update) => factor_name(&update.table.relation).into_iter().collect(),
        Statement::Delete(delete) => match &delete.from {
            FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => tables
                .iter()
                .filter_map(|table: &TableWithJoins| factor_name(&table.relation))
                .collect(),
        },
        Statement::Merge(merge) => factor_name(&merge.table).into_iter().collect(),
        _ => return None,
    })
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

    fn statement(&self, statement: &Statement) -> Option<()> {
        written_names(statement)?
            .into_iter()
            .any(|name| {
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

    fn call(&self) {}
}
