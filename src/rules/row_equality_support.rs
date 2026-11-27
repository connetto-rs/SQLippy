//! The columns that foreign keys and unique keys force rows known to exist
//! to hold one value in.

use std::{cell::RefCell, collections::HashMap, ptr, rc::Rc};

use sql_traits::{
    errors::LookupError,
    structs::{Assumption, IdentifierCase, Outcomes},
    traits::{CheckConstraintLike, ColumnLike, DatabaseLike, ForeignKeyLike, TableLike},
};
use sqlparser::ast::{Expr, Ident};

use crate::rules::{
    closed_set_support::same_identity,
    key_support::{Key, checked_each_statement, equality_keys, key_pairs, no_inheritors},
};

/// Pairs of columns of two rows.
pub(crate) type ColumnPairs<'db, DB> = Vec<(
    &'db <DB as DatabaseLike>::Column,
    &'db <DB as DatabaseLike>::Column,
)>;

/// The answers of [`TableFacts::forces`], by the column asked about and the
/// columns given to hold a value.
type ForcingAnswers<DB> = HashMap<
    (
        *const <DB as DatabaseLike>::Column,
        Vec<*const <DB as DatabaseLike>::Column>,
    ),
    bool,
>;

/// The unique keys telling rows of each table apart, by the table.
type TableKeys<'db, DB> = HashMap<*const <DB as DatabaseLike>::Table, Rc<[Key<'db, DB>]>>;

/// The columns the enforced and validated checks of each table involve, by
/// the table.
type CheckedColumns<'db, DB> =
    HashMap<*const <DB as DatabaseLike>::Table, Rc<[&'db <DB as DatabaseLike>::Column]>>;

/// What the constraints of tables tell of their rows, each answer read once
/// and shared by every [`RowEqualities`] reading it.
pub(crate) struct TableFacts<'db, DB: DatabaseLike> {
    database: &'db DB,
    forcing: RefCell<ForcingAnswers<DB>>,
    keys: RefCell<TableKeys<'db, DB>>,
    checked: RefCell<CheckedColumns<'db, DB>>,
}

impl<'db, DB: DatabaseLike> TableFacts<'db, DB> {
    /// No answers yet over `database`.
    pub(crate) fn new(database: &'db DB) -> Self {
        Self {
            database,
            forcing: RefCell::new(HashMap::new()),
            keys: RefCell::new(HashMap::new()),
            checked: RefCell::new(HashMap::new()),
        }
    }

    /// Whether `column` holds a value in every row whose `NOT NULL` columns
    /// and the nullable columns in `given`, of the same table and in the
    /// order it declares them, hold one, as `NOT NULL` or the enforced and
    /// validated checks of its table force.
    fn forces(
        &self,
        column: &'db DB::Column,
        given: &[&'db DB::Column],
    ) -> Result<bool, LookupError> {
        let database = self.database;
        if !column.is_nullable(database)? {
            return Ok(true);
        }
        let checked = self.checked_columns(column.table(database))?;
        if !checked.iter().any(|other| ptr::eq(*other, column)) {
            return Ok(false);
        }
        let given: Vec<&'db DB::Column> = given
            .iter()
            .copied()
            .filter(|held| checked.iter().any(|other| ptr::eq(*other, *held)))
            .collect();
        let key = (
            ptr::from_ref(column),
            given.iter().map(|other| ptr::from_ref(*other)).collect(),
        );
        if let Some(forced) = self.forcing.borrow().get(&key) {
            return Ok(*forced);
        }
        let forced = self.checks_force(column, &checked, &given)?;
        self.forcing.borrow_mut().insert(key, forced);
        Ok(forced)
    }

    /// Whether the enforced and validated checks of the table of the
    /// nullable `column` force it to hold a value while its `NOT NULL`
    /// columns and the columns in `given` hold one. The checks involve the
    /// columns in `checked`, and no other column bears on them.
    fn checks_force(
        &self,
        column: &'db DB::Column,
        checked: &[&'db DB::Column],
        given: &[&'db DB::Column],
    ) -> Result<bool, LookupError> {
        let database = self.database;
        let table = column.table(database);
        let mut assumptions = Vec::new();
        for check in table.check_constraints(database)? {
            if check.is_enforced() && check.is_validated(database)? {
                assumptions.push(Assumption::Check(check));
            }
        }
        let mut valued = Vec::new();
        for other in checked {
            if !other.is_nullable(database)? || given.iter().any(|held| ptr::eq(*held, *other)) {
                valued.push(Expr::IsNotNull(Box::new(quoted(
                    &other.stored_column_name(),
                ))));
            }
        }
        assumptions.extend(valued.iter().map(|expression| Assumption::Expression {
            expression,
            outcomes: Outcomes::TRUE,
        }));
        let null = Expr::IsNull(Box::new(quoted(&column.stored_column_name())));
        Ok(!table
            .truth_under(database, &null, IdentifierCase::AsWritten, &assumptions)?
            .outcomes
            .truth)
    }

    /// The columns the enforced and validated checks of `table` involve.
    fn checked_columns(&self, table: &'db DB::Table) -> Result<Rc<[&'db DB::Column]>, LookupError> {
        if let Some(checked) = self.checked.borrow().get(&ptr::from_ref(table)) {
            return Ok(Rc::clone(checked));
        }
        let database = self.database;
        let mut checked: Vec<&'db DB::Column> = Vec::new();
        for check in table.check_constraints(database)? {
            if !check.is_enforced() || !check.is_validated(database)? {
                continue;
            }
            for column in check.columns(database)? {
                if !checked.iter().any(|other| ptr::eq(*other, column)) {
                    checked.push(column);
                }
            }
        }
        let checked: Rc<[&'db DB::Column]> = checked.into();
        self.checked
            .borrow_mut()
            .insert(ptr::from_ref(table), Rc::clone(&checked));
        Ok(checked)
    }

    /// The unique keys telling rows of `table` apart, none when another
    /// table inherits from it.
    fn keys(&self, table: &'db DB::Table) -> Result<Rc<[Key<'db, DB>]>, LookupError> {
        if let Some(keys) = self.keys.borrow().get(&ptr::from_ref(table)) {
            return Ok(Rc::clone(keys));
        }
        let keys: Rc<[Key<'db, DB>]> = if no_inheritors(self.database, table)? {
            equality_keys(self.database, table)?.into()
        } else {
            Rc::from([])
        };
        self.keys
            .borrow_mut()
            .insert(ptr::from_ref(table), Rc::clone(&keys));
        Ok(keys)
    }
}

/// Rows known to exist, with the columns they hold one value in. A foreign
/// key that checks a row adds the row it references, holding the values of
/// its host columns, and two rows of one table that hold the same values in
/// a unique key are one row, holding the same value in every column.
pub(crate) struct RowEqualities<'f, 'db, DB: DatabaseLike> {
    database: &'db DB,
    facts: &'f TableFacts<'db, DB>,
    /// The rows added as known, followed by the rows foreign keys reach.
    rows: Vec<Known<'db, DB>>,
    /// The number of rows added as known.
    known: usize,
    /// The row and column of each cell.
    cells: Vec<(usize, &'db DB::Column)>,
    /// The cell each cell was joined to, or the cell itself when it stands
    /// for the cells holding its value.
    joined: Vec<usize>,
    /// Whether the cells a standing cell stands for hold a value, never
    /// `NULL`.
    valued: Vec<bool>,
    /// The tables of the rows so far.
    met: Vec<&'db DB::Table>,
    /// The number of foreign keys the tables met declare.
    limit: usize,
}

/// A row known to exist.
struct Known<'db, DB: DatabaseLike> {
    table: &'db DB::Table,
    /// The number of foreign keys followed to reach the row.
    depth: usize,
    /// The row this one turned out to be, whose cells it shares.
    same_as: Option<usize>,
    /// The positions among the foreign keys of its table of those followed
    /// from it.
    followed: Vec<usize>,
}

impl<'f, 'db, DB: DatabaseLike> RowEqualities<'f, 'db, DB> {
    /// No rows, reading the constraints of tables through `facts`.
    pub(crate) fn new(facts: &'f TableFacts<'db, DB>) -> Self {
        Self {
            database: facts.database,
            facts,
            rows: Vec::new(),
            known: 0,
            cells: Vec::new(),
            joined: Vec::new(),
            valued: Vec::new(),
            met: Vec::new(),
            limit: 0,
        }
    }

    /// Adds a row of `table` known to exist, before any is followed, and
    /// returns its index.
    pub(crate) fn add(&mut self, table: &'db DB::Table) -> usize {
        self.known += 1;
        self.push(table, 0)
    }

    /// Adds a row of `table` reached through `depth` foreign keys.
    fn push(&mut self, table: &'db DB::Table, depth: usize) -> usize {
        self.rows.push(Known {
            table,
            depth,
            same_as: None,
            followed: Vec::new(),
        });
        self.rows.len() - 1
    }

    /// States that `column` of `row` and `other_column` of `other` hold one
    /// value, never `NULL`, each named by its stored name. A column its
    /// table lacks states nothing.
    pub(crate) fn equate(
        &mut self,
        row: usize,
        column: &str,
        other: usize,
        other_column: &str,
    ) -> Result<(), LookupError> {
        let (Some(column), Some(other_column)) =
            (self.column(row, column)?, self.column(other, other_column)?)
        else {
            return Ok(());
        };
        let left = self.cell_of(row, column)?;
        let right = self.cell_of(other, other_column)?;
        self.join(left, right);
        self.hold_value(left);
        Ok(())
    }

    /// Follows every foreign key that checks a row and joins every two rows
    /// one unique key tells are one, until neither adds anything. A row a
    /// foreign key reached follows only a foreign key one of whose host
    /// columns holds a value of a known row, and lies within as many foreign
    /// keys of a known row as the tables met so far declare, which bounds a
    /// cycle of foreign keys every row holds a value in.
    pub(crate) fn close(&mut self) -> Result<(), LookupError> {
        loop {
            let mut changed = false;
            for row in 0..self.rows.len() {
                let table = self.rows[row].table;
                if !self.met.iter().any(|met| ptr::eq(*met, table)) {
                    self.met.push(table);
                    self.limit += table.foreign_keys(self.database)?.count();
                }
            }
            for row in 0..self.rows.len() {
                changed |= self.follow(row)?;
            }
            for row in 0..self.rows.len() {
                for other in row + 1..self.rows.len() {
                    changed |= self.identify(row, other)?;
                }
            }
            if !changed {
                return Ok(());
            }
        }
    }

    /// Each column of `row` paired with the first column of `other`, in the
    /// order its table declares them, holding the same value.
    pub(crate) fn shared_columns(
        &self,
        row: usize,
        other: usize,
    ) -> Result<ColumnPairs<'db, DB>, LookupError> {
        let database = self.database;
        let mut shared = Vec::new();
        for column in self.rows[row].table.columns(database)? {
            let Some(cell) = self.find_cell(row, column) else {
                continue;
            };
            for candidate in self.rows[other].table.columns(database)? {
                if self
                    .find_cell(other, candidate)
                    .is_some_and(|found| self.root(found) == self.root(cell))
                {
                    shared.push((column, candidate));
                    break;
                }
            }
        }
        Ok(shared)
    }

    /// Follows each foreign key that checks `row` and was not followed from
    /// it, when `row` lies within as many foreign keys of a known row as the
    /// tables met declare, and returns whether one was followed. A key
    /// checks the row when every host column holds a value, as the table's
    /// checks may force a host column to given the others, or one does under
    /// `MATCH FULL`, and every host column then holds the value of the
    /// referenced column it pairs with, compared by identity. A row a
    /// foreign key reached follows a key only when one of its host columns
    /// holds a value of a known row.
    fn follow(&mut self, row: usize) -> Result<bool, LookupError> {
        let Known {
            table,
            depth,
            same_as,
            ..
        } = self.rows[row];
        let database = self.database;
        if same_as.is_some() || depth >= self.limit {
            return Ok(false);
        }
        let mut changed = false;
        for (position, foreign_key) in table.foreign_keys(database)?.enumerate() {
            if self.rows[row].followed.contains(&position) {
                continue;
            }
            if !checked_each_statement(database, foreign_key)? {
                continue;
            }
            let pairs = key_pairs(database, foreign_key)?;
            if row >= self.known
                && !pairs.iter().any(|(host, _)| {
                    self.find_cell(row, host)
                        .is_some_and(|cell| self.holds_known_value(cell))
                })
            {
                continue;
            }
            let mut hosts = Vec::with_capacity(pairs.len());
            for (host, _) in &pairs {
                hosts.push(self.cell_of(row, host)?);
            }
            if !self.checks_row(row, foreign_key.match_full(database), &pairs, &hosts)? {
                continue;
            }
            self.rows[row].followed.push(position);
            let referenced = self.push(foreign_key.referenced_table(database)?, depth + 1);
            for ((host, target), cell) in pairs.into_iter().zip(hosts) {
                let target_cell = self.cell_of(referenced, target)?;
                self.hold_value(cell);
                self.hold_value(target_cell);
                if same_identity(database, host, target)? {
                    self.join(cell, target_cell);
                }
            }
            changed = true;
        }
        Ok(changed)
    }

    /// Whether a foreign key over `pairs`, under `MATCH FULL` when `full` is
    /// set, checks `row`, whose cell of each host column is in `hosts`. The
    /// table's checks are read only for host columns whose cell holds no
    /// value.
    fn checks_row(
        &self,
        row: usize,
        full: bool,
        pairs: &[(&'db DB::Column, &'db DB::Column)],
        hosts: &[usize],
    ) -> Result<bool, LookupError> {
        let unvalued: Vec<&'db DB::Column> = pairs
            .iter()
            .zip(hosts)
            .filter(|(_, cell)| !self.holds_value(**cell))
            .map(|((host, _), _)| *host)
            .collect();
        if unvalued.is_empty() || (full && unvalued.len() < hosts.len()) {
            return Ok(true);
        }
        for host in unvalued {
            let forced = self.checks_force_value(row, host)?;
            if full && forced {
                return Ok(true);
            }
            if !full && !forced {
                return Ok(false);
            }
        }
        Ok(!full)
    }

    /// Whether `column` of `row` holds a value, as the enforced and
    /// validated checks of its table force while every `NOT NULL` column and
    /// every column of `row` whose cell holds a value hold one.
    fn checks_force_value(&self, row: usize, column: &'db DB::Column) -> Result<bool, LookupError> {
        let row = self.canonical(row);
        let mut given = Vec::new();
        for other in self.rows[row].table.columns(self.database)? {
            if other.is_nullable(self.database)?
                && self
                    .find_cell(row, other)
                    .is_some_and(|cell| self.holds_value(cell))
            {
                given.push(other);
            }
        }
        self.facts.forces(column, &given)
    }

    /// Joins `other` into `row` when both are rows of one table nothing
    /// inherits from, holding the same values in every column of one of its
    /// unique keys, and returns whether it did.
    fn identify(&mut self, row: usize, other: usize) -> Result<bool, LookupError> {
        let table = self.rows[row].table;
        if self.rows[row].same_as.is_some()
            || self.rows[other].same_as.is_some()
            || !ptr::eq(table, self.rows[other].table)
        {
            return Ok(false);
        }
        let mut agree = false;
        for key in self.facts.keys(table)?.iter() {
            if !key.is_empty() && self.key_agrees(row, other, key)? {
                agree = true;
                break;
            }
        }
        if !agree {
            return Ok(false);
        }
        let made = self.cells.len();
        self.rows[other].same_as = Some(row);
        self.rows[row].depth = self.rows[row].depth.min(self.rows[other].depth);
        for cell in 0..made {
            let (own, column) = self.cells[cell];
            if own == other {
                let kept = self.cell_of(row, column)?;
                self.join(kept, cell);
            }
        }
        Ok(true)
    }

    /// Whether `row` and `other` hold one value, never `NULL`, in every
    /// column of `key`, stating the values the checks of their table force.
    fn key_agrees(
        &mut self,
        row: usize,
        other: usize,
        key: &[&'db DB::Column],
    ) -> Result<bool, LookupError> {
        let mut cells = Vec::with_capacity(key.len());
        for column in key {
            match (self.find_cell(row, column), self.find_cell(other, column)) {
                (Some(left), Some(right)) if self.root(left) == self.root(right) => {
                    cells.push((*column, left));
                }
                _ => return Ok(false),
            }
        }
        for (column, cell) in cells {
            if !self.holds_value(cell) {
                if !self.checks_force_value(row, column)? {
                    return Ok(false);
                }
                self.hold_value(cell);
            }
        }
        Ok(true)
    }

    /// The column of the table of `row` stored as `name`.
    fn column(&self, row: usize, name: &str) -> Result<Option<&'db DB::Column>, LookupError> {
        Ok(self.rows[row]
            .table
            .columns(self.database)?
            .find(|column| column.stored_column_name() == name))
    }

    /// The row `row` turned out to be, or `row` itself.
    fn canonical(&self, mut row: usize) -> usize {
        while let Some(same) = self.rows[row].same_as {
            row = same;
        }
        row
    }

    /// The cell of `column` of `row`, or of the row it turned out to be, when
    /// one was made.
    fn find_cell(&self, row: usize, column: &DB::Column) -> Option<usize> {
        let row = self.canonical(row);
        self.cells
            .iter()
            .position(|(own, cell)| *own == row && ptr::eq(*cell, column))
    }

    /// The cell of `column` of `row`, or of the row it turned out to be, made
    /// when missing, holding a value when the column is `NOT NULL`.
    fn cell_of(&mut self, row: usize, column: &'db DB::Column) -> Result<usize, LookupError> {
        if let Some(cell) = self.find_cell(row, column) {
            return Ok(cell);
        }
        let cell = self.cells.len();
        self.cells.push((self.canonical(row), column));
        self.joined.push(cell);
        self.valued.push(!column.is_nullable(self.database)?);
        Ok(cell)
    }

    /// The cell standing for the cells holding the value of `cell`.
    fn root(&self, mut cell: usize) -> usize {
        while self.joined[cell] != cell {
            cell = self.joined[cell];
        }
        cell
    }

    /// Whether `cell` holds a value.
    fn holds_value(&self, cell: usize) -> bool {
        self.valued[self.root(cell)]
    }

    /// Whether `cell` holds the value of a column of a known row.
    fn holds_known_value(&self, cell: usize) -> bool {
        let root = self.root(cell);
        self.cells
            .iter()
            .enumerate()
            .any(|(other, (row, _))| *row < self.known && self.root(other) == root)
    }

    /// States that `cell` holds a value.
    fn hold_value(&mut self, cell: usize) {
        let root = self.root(cell);
        self.valued[root] = true;
    }

    /// States that `left` and `right` hold one value.
    fn join(&mut self, left: usize, right: usize) {
        let (left, right) = (self.root(left), self.root(right));
        if left != right {
            self.joined[right] = left;
            self.valued[left] |= self.valued[right];
        }
    }
}

/// A reference to the column stored as `name`.
fn quoted(name: &str) -> Expr {
    Expr::Identifier(Ident::with_quote('"', name))
}
