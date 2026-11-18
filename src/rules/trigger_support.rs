//! Facts about triggers and the functions they run, shared by the trigger
//! rules.

use sql_traits::traits::{DatabaseLike, FunctionLike, TriggerLike};
use sqlparser::{
    ast::{
        Delete, Expr, FromTable, Ident, Insert, Merge, ObjectName, Query, SelectItem, Statement,
        TableFactor, TableObject, TableWithJoins, TriggerEvent, TriggerObject, TriggerObjectKind,
        TriggerPeriod, Update,
    },
    keywords::Keyword,
    tokenizer::Token,
};

use crate::rules::{cte_support::stored_table, function_reach_support::Sought};

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
        let elsewhere = |name: &ObjectName| {
            !matches!(
                stored_table(self.database, name, None),
                Ok(Some(table)) if table == self.table
            )
        };
        let writes_elsewhere = match statement {
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
            }) => elsewhere(name),
            Statement::Delete(Delete {
                from: FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables),
                ..
            }) => tables.iter().any(
                |table| matches!(&table.relation, TableFactor::Table { name, .. } if elsewhere(name)),
            ),
            _ => false,
        };
        writes_elsewhere.then_some(())
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
