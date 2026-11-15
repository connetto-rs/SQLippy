//! The `WITH` items a walk over a query can see, and the item a relation
//! name reads, shared by the rules on common table expressions.

use std::ptr;

use sql_traits::utils::identifier_resolution::identifiers_match;
use sqlparser::ast::{Cte, Ident, ObjectName, ObjectNamePart, Query, SetExpr};

/// The `WITH` items visible where a walk over a query stands, scoped as
/// PostgreSQL scopes them.
///
/// An item's body sees the items before it, or every item under `WITH
/// RECURSIVE`, and the rest of the query sees them all, so a body naming its
/// own item reads the stored relation unless the `WITH` is recursive. The
/// walk calls [`enter`](Self::enter) before visiting each query and
/// [`leave`](Self::leave) after it.
#[derive(Default)]
pub(crate) struct WithScopes {
    frames: Vec<WithFrame>,
}

/// The items one `WITH` clause binds, identified by address since the walk
/// borrows each query only for the length of one visit.
struct WithFrame {
    owner: *const Query,
    bodies: Vec<*const Query>,
    names: Vec<Ident>,
    recursive: bool,
    /// How many items, from the first, the walk currently sees.
    visible: usize,
    /// The item whose body the walk stands in.
    current: Option<usize>,
}

/// The `WITH` item a relation name reads.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ItemBinding {
    /// The address of the query whose `WITH` clause holds the item.
    pub(crate) owner: *const Query,
    /// The item's position in that clause.
    pub(crate) item: usize,
    /// Whether the name stands inside the item's own body.
    pub(crate) in_own_body: bool,
}

impl WithScopes {
    pub(crate) fn enter(&mut self, query: &Query) {
        if let Some(frame) = self.frames.last_mut()
            && let Some(position) = frame.bodies.iter().position(|body| ptr::eq(*body, query))
        {
            frame.visible = if frame.recursive {
                frame.names.len()
            } else {
                position
            };
            frame.current = Some(position);
        }
        if let Some(with) = &query.with {
            self.frames.push(WithFrame {
                owner: query,
                bodies: with
                    .cte_tables
                    .iter()
                    .map(|item| &raw const *item.query)
                    .collect(),
                names: with
                    .cte_tables
                    .iter()
                    .map(|item| item.alias.name.clone())
                    .collect(),
                recursive: with.recursive,
                visible: 0,
                current: None,
            });
        }
    }

    pub(crate) fn leave(&mut self, query: &Query) {
        if self
            .frames
            .last()
            .is_some_and(|frame| ptr::eq(frame.owner, query))
        {
            self.frames.pop();
        }
        if let Some(frame) = self.frames.last_mut()
            && let Some(position) = frame.bodies.iter().position(|body| ptr::eq(*body, query))
        {
            frame.current = None;
            if !frame.recursive {
                frame.visible = position + 1;
            }
        }
    }

    /// The visible `WITH` item `name` reads, or `None` for a stored relation.
    /// A schema-qualified name never reads an item.
    pub(crate) fn binding(&self, name: &ObjectName) -> Option<ItemBinding> {
        let [ObjectNamePart::Identifier(written)] = name.0.as_slice() else {
            return None;
        };
        self.unqualified_binding(written)
    }

    /// The visible `WITH` item the unqualified name `written` reads, or
    /// `None` for a stored relation.
    pub(crate) fn unqualified_binding(&self, written: &Ident) -> Option<ItemBinding> {
        self.frames.iter().rev().find_map(|frame| {
            frame.names[..frame.visible]
                .iter()
                .position(|item| same_name(item, written))
                .map(|item| ItemBinding {
                    owner: frame.owner,
                    item,
                    in_own_body: frame.current == Some(item),
                })
        })
    }
}

/// Whether two written identifiers name the same object.
pub(crate) fn same_name(left: &Ident, right: &Ident) -> bool {
    identifiers_match(
        &left.value,
        left.quote_style.is_some(),
        &right.value,
        right.quote_style.is_some(),
    )
}

/// Whether a `WITH` item's body is an `INSERT`, `UPDATE`, `DELETE` or
/// `MERGE`, which PostgreSQL runs whether or not anything reads the item.
pub(crate) fn modifies_data(item: &Cte) -> bool {
    matches!(
        item.query.body.as_ref(),
        SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Delete(_) | SetExpr::Merge(_)
    )
}

/// Calls `read` with each unqualified name the `TABLE` commands of a set
/// expression read, leaving nested queries to their own visit.
pub(crate) fn table_commands(body: &SetExpr, read: &mut dyn FnMut(&Ident)) {
    match body {
        SetExpr::Table(table) if table.schema_name.is_none() => {
            if let Some(name) = &table.table_name {
                read(name);
            }
        }
        SetExpr::SetOperation { left, right, .. } => {
            table_commands(left, read);
            table_commands(right, read);
        }
        _ => {}
    }
}
