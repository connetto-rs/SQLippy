//! Submodule providing the `JoinOnNonKeyColumns` rule.

use std::{borrow::Cow, ops::ControlFlow, ptr};

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnDefinitionScope},
    traits::{ColumnLike, DatabaseLike, TableLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{
    BinaryOperator, Expr, Ident, JoinConstraint, ObjectName, Query, Select, SetExpr, Statement,
    TableAlias, TableFactor, TableWithJoins, Visit, Visitor,
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::{join_constraint, stored_table},
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
        key_support::{equality_keys, references},
        policy_support::conjuncts,
        statement_support::{check_query_selects, query_root, root_query, statement_root},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// A stored column of a catalog table that a `SELECT`'s own `FROM` names.
struct Stored<'s, DB: DatabaseLike> {
    /// The position of the table among the `SELECT`'s relations.
    relation: usize,
    /// The name the query refers to the table by.
    name: &'s Ident,
    /// The catalog table.
    table: &'s DB::Table,
    /// The stored column.
    column: &'s DB::Column,
}

/// What one operand of an equality reads.
enum Operand<'s, DB: DatabaseLike> {
    /// A stored column of one of the `SELECT`'s own tables.
    Stored(Stored<'s, DB>),
    /// One value while the `SELECT` runs: a literal, a parameter, a variable
    /// or a column of an enclosing query.
    Fixed,
    /// Anything else, such as a computed value or a column of a derived
    /// table.
    Other,
}

/// An equality between stored columns of two of a `SELECT`'s tables.
struct Equality<'s, DB: DatabaseLike> {
    left: Stored<'s, DB>,
    right: Stored<'s, DB>,
    /// The equality as written, or as a `USING` or `NATURAL` join states it.
    written: String,
}

impl<DB: DatabaseLike> Equality<'_, DB> {
    /// The positions of the two tables, the lower first.
    fn tables(&self) -> (usize, usize) {
        let (left, right) = (self.left.relation, self.right.relation);
        (left.min(right), left.max(right))
    }
}

/// The equalities between a `SELECT`'s own tables and the columns its
/// conditions fix to one value.
struct Links<'s, 'r, 'a, 'b, 'c, DB: DatabaseLike> {
    database: &'s DB,
    scope: &'s ColumnDefinitionScope<'a, 'b, 'c, DB>,
    relations: &'r [&'s TableFactor],
    /// The name and catalog table of each relation, `None` for a `WITH`
    /// item, a view, a derived table or a function.
    tables: Vec<Option<(&'s Ident, &'s DB::Table)>>,
    equalities: Vec<Equality<'s, DB>>,
    fixed: Vec<(usize, &'s DB::Column)>,
}

/// The relations one comma-separated `FROM` item joins, parenthesized joins
/// flattened, in written order.
fn relations<'s>(item: &'s TableWithJoins, found: &mut Vec<&'s TableFactor>) {
    flatten(&item.relation, found);
    for join in &item.joins {
        flatten(&join.relation, found);
    }
}

/// Appends `factor`, or the relations of the parenthesized join it is.
fn flatten<'s>(factor: &'s TableFactor, found: &mut Vec<&'s TableFactor>) {
    match factor {
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => relations(table_with_joins, found),
        _ => found.push(factor),
    }
}

/// The name a relation written by name is referred to by in the query, and
/// its alias.
fn exposed(factor: &TableFactor) -> Option<(&Ident, Option<&TableAlias>)> {
    let TableFactor::Table {
        name,
        alias,
        args: None,
        ..
    } = factor
    else {
        return None;
    };
    alias
        .as_ref()
        .map(|alias| &alias.name)
        .or_else(|| name.0.last().and_then(|part| part.as_ident()))
        .map(|exposed| (exposed, alias.as_ref()))
}

/// The reference `relation.column`.
fn qualified(relation: &Ident, column: &Ident) -> Expr {
    Expr::CompoundIdentifier(vec![relation.clone(), column.clone()])
}

impl<'s, DB: DatabaseLike> Links<'s, '_, '_, '_, '_, DB> {
    /// What `expression` reads.
    fn operand(&self, expression: &Expr) -> Result<Operand<'s, DB>, LookupError> {
        match expression {
            Expr::Nested(inner) => self.operand(inner),
            Expr::Value(_) => Ok(Operand::Fixed),
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
                // A name no relation in scope holds is a parameter or a
                // variable of the body running the query.
                let Some((definition, binding)) = self.scope.resolve_column_binding(expression)?
                else {
                    return Ok(Operand::Fixed);
                };
                let Some(entry) = binding.entry() else {
                    return Ok(Operand::Other);
                };
                let Some(relation) = self.own(entry.factor(), binding.relation()) else {
                    return Ok(Operand::Fixed);
                };
                Ok(match (definition, self.tables[relation]) {
                    (ColumnDefinition::Base { table, column, .. }, Some((name, own)))
                        if table == own =>
                    {
                        Operand::Stored(Stored {
                            relation,
                            name,
                            table: own,
                            column,
                        })
                    }
                    _ => Operand::Other,
                })
            }
            _ => Ok(Operand::Other),
        }
    }

    /// The position of the relation of this `SELECT` a reference reached
    /// through `factor` under the name `relation`, or `None` for a relation
    /// of an enclosing query. A column of a view reaches a `FROM` item of
    /// the view's definition, so the name tells it apart.
    fn own(&self, factor: &TableFactor, relation: Option<(&str, bool)>) -> Option<usize> {
        self.relations
            .iter()
            .position(|own| ptr::eq(*own, factor))
            .or_else(|| {
                let (name, quoted) = relation?;
                let name = normalize_identifier(name, quoted);
                self.relations.iter().position(|own| {
                    exposed(own).is_some_and(|(exposed, _)| {
                        normalize_identifier(&exposed.value, exposed.quote_style.is_some()) == name
                    })
                })
            })
    }

    /// Reads the equalities of the `AND` chain `condition`.
    fn condition(&mut self, condition: &Expr) -> Result<(), LookupError> {
        for conjunct in conjuncts(condition) {
            let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = conjunct
            else {
                continue;
            };
            match (self.operand(left)?, self.operand(right)?) {
                (Operand::Stored(left), Operand::Stored(right))
                    if left.relation != right.relation =>
                {
                    self.equalities.push(Equality {
                        left,
                        right,
                        written: conjunct.to_string(),
                    });
                }
                (Operand::Stored(stored), Operand::Fixed)
                | (Operand::Fixed, Operand::Stored(stored)) => {
                    self.fixed.push((stored.relation, stored.column));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Reads the equality a `USING` or `NATURAL` join states on `column`
    /// between the relation at `right` and each relation at `left` holding
    /// it.
    fn shared(&mut self, left: &[usize], right: usize, column: &Ident) -> Result<(), LookupError> {
        let Some((right_name, _)) = exposed(self.relations[right]) else {
            return Ok(());
        };
        let right_reference = qualified(right_name, column);
        for &relation in left {
            let Some((left_name, _)) = exposed(self.relations[relation]) else {
                continue;
            };
            let left_reference = qualified(left_name, column);
            if let (Operand::Stored(left_column), Operand::Stored(right_column)) = (
                self.operand(&left_reference)?,
                self.operand(&right_reference)?,
            ) && left_column.relation == relation
            {
                self.equalities.push(Equality {
                    left: left_column,
                    right: right_column,
                    written: format!("{left_reference} = {right_reference}"),
                });
            }
        }
        Ok(())
    }

    /// The names the relation at `position` shows its columns under, or none
    /// for a relation that is not a catalog table.
    fn visible(&self, position: usize) -> Result<Vec<Ident>, LookupError> {
        let factor = self.relations[position];
        let (TableFactor::Table { name, .. }, Some((_, alias))) = (factor, exposed(factor)) else {
            return Ok(Vec::new());
        };
        let Some(table) = stored_table(self.database, name, None)? else {
            return Ok(Vec::new());
        };
        let renamed = alias.map_or(&[][..], |alias| alias.columns.as_slice());
        Ok(table
            .columns(self.database)?
            .enumerate()
            .map(|(position, column)| {
                renamed.get(position).map_or_else(
                    || Ident::with_quote('"', column.column_name()),
                    |renamed| renamed.name.clone(),
                )
            })
            .collect())
    }

    /// Reads the conditions of the joins of one `FROM` item, the relations
    /// before `offset` belonging to an enclosing item.
    fn joins(&mut self, item: &TableWithJoins, offset: usize) -> Result<usize, LookupError> {
        let mut next = self.factor(&item.relation, offset)?;
        for join in &item.joins {
            let right = next;
            next = self.factor(&join.relation, next)?;
            let left: Vec<usize> = (offset..right).collect();
            match join_constraint(&join.join_operator) {
                Some(JoinConstraint::On(condition)) => self.condition(condition)?,
                Some(JoinConstraint::Using(names) | JoinConstraint::UsingAlias(names, _))
                    if next == right + 1 =>
                {
                    for column in names
                        .iter()
                        .filter_map(|name| name.0.last().and_then(|part| part.as_ident()))
                    {
                        self.shared(&left, right, column)?;
                    }
                }
                Some(JoinConstraint::Natural) if next == right + 1 => {
                    for column in self.visible(right)? {
                        self.shared(&left, right, &column)?;
                    }
                }
                _ => {}
            }
        }
        Ok(next)
    }

    /// Reads the joins inside `factor` when it is a parenthesized join, and
    /// returns the position after its relations.
    fn factor(&mut self, factor: &TableFactor, position: usize) -> Result<usize, LookupError> {
        match factor {
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => self.joins(table_with_joins, position),
            _ => Ok(position + 1),
        }
    }

    /// Whether `columns` of `table` cover a unique key through which each
    /// row of the other side matches at most one of its rows.
    fn covers_key(&self, table: &DB::Table, columns: &[&DB::Column]) -> Result<bool, LookupError> {
        Ok(equality_keys(self.database, table)?
            .iter()
            .any(|key| key.iter().all(|column| columns.contains(column))))
    }

    /// The foreign key condition that links the tables of `first` and
    /// `second`, such as `e.project_id = p.id`.
    fn link(
        &self,
        first: &Stored<'s, DB>,
        second: &Stored<'s, DB>,
    ) -> Result<Option<String>, LookupError> {
        for (child, parent) in [(first, second), (second, first)] {
            if let Some(pairs) = references(self.database, child.table, parent.table)?.first() {
                let conditions: Vec<String> = pairs
                    .iter()
                    .map(|(host, referenced)| {
                        format!(
                            "{}.{} = {}.{}",
                            child.name,
                            host.column_name(),
                            parent.name,
                            referenced.column_name()
                        )
                    })
                    .collect();
                return Ok(Some(conditions.join(" AND ")));
            }
        }
        Ok(None)
    }

    /// The columns of the table at `position` that `between` equates or the
    /// conditions fix.
    fn equated(&self, position: usize, between: &[&Equality<'s, DB>]) -> Vec<&'s DB::Column> {
        self.fixed
            .iter()
            .filter(|(relation, _)| *relation == position)
            .map(|(_, column)| *column)
            .chain(
                between
                    .iter()
                    .flat_map(|equality| [&equality.left, &equality.right])
                    .filter(|end| end.relation == position)
                    .map(|end| end.column),
            )
            .collect()
    }

    /// The joins between two tables whose equalities cover a unique key of
    /// neither, each as its description and its condition.
    fn findings(&self) -> Result<Vec<(String, String)>, LookupError> {
        let mut pairs: Vec<((usize, usize), &Equality<'s, DB>)> = self
            .equalities
            .iter()
            .map(|equality| (equality.tables(), equality))
            .collect();
        pairs.sort_by_key(|(pair, _)| *pair);
        pairs.dedup_by_key(|(pair, _)| *pair);
        let mut found = Vec::new();
        for (pair, representative) in pairs {
            let between: Vec<&Equality<'s, DB>> = self
                .equalities
                .iter()
                .filter(|equality| equality.tables() == pair)
                .collect();
            let (first, second) = if representative.left.relation == pair.0 {
                (&representative.left, &representative.right)
            } else {
                (&representative.right, &representative.left)
            };
            if self.covers_key(first.table, &self.equated(pair.0, &between))?
                || self.covers_key(second.table, &self.equated(pair.1, &between))?
            {
                continue;
            }
            let condition = between
                .iter()
                .map(|equality| equality.written.as_str())
                .collect::<Vec<_>>()
                .join(" AND ");
            let foreign_key = self.link(first, second)?.map_or_else(String::new, |link| {
                format!(" instead of their foreign key `{link}`")
            });
            let description = format!(
                "a join of '{}' and '{}' on `{condition}`{foreign_key}",
                first.table.table_name(),
                second.table.table_name()
            );
            found.push((description, condition));
        }
        Ok(found)
    }
}

/// Whether `name` names a `WITH` item, one of `ctes`, rather than a stored
/// relation.
fn names_with_item(name: &ObjectName, ctes: &[String]) -> bool {
    match name.0.as_slice() {
        [part] => part.as_ident().is_some_and(|ident| {
            ctes.iter()
                .any(|cte| *cte == normalize_identifier(&ident.value, ident.quote_style.is_some()))
        }),
        _ => false,
    }
}

/// The joins of `select` whose equalities cover a unique key of neither of
/// the two tables they join, read in `scope` under the `WITH` items `ctes`
/// its statement declares.
fn non_key_joins<DB: DatabaseLike>(
    database: &DB,
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    select: &Select,
    ctes: &[String],
) -> Result<Vec<(String, String)>, LookupError> {
    let mut own = Vec::new();
    for item in &select.from {
        relations(item, &mut own);
    }
    if own.len() < 2 {
        return Ok(Vec::new());
    }
    let mut tables = Vec::with_capacity(own.len());
    for factor in &own {
        let table = match factor {
            TableFactor::Table {
                name, args: None, ..
            } if !names_with_item(name, ctes) => stored_table(database, name, None)?,
            _ => None,
        };
        tables.push(
            exposed(factor)
                .zip(table)
                .map(|((name, _), table)| (name, table)),
        );
    }
    let mut links = Links {
        database,
        scope,
        relations: &own,
        tables,
        equalities: Vec::new(),
        fixed: Vec::new(),
    };
    if let Some(selection) = &select.selection {
        links.condition(selection)?;
    }
    let mut offset = 0;
    for item in &select.from {
        offset = links.joins(item, offset)?;
    }
    links.findings()
}

/// Reads every query of a node under the scope of its outermost query, an
/// `UPDATE` or `DELETE` as the `SELECT` over its relations, and an `UPDATE`
/// or `DELETE` a `WITH` item runs as that `SELECT` under the `WITH` clause.
struct Roots<'d, DB: DatabaseLike> {
    database: &'d DB,
    /// How many enclosing queries or data-modifying statements were read.
    depth: usize,
    found: Vec<(String, String)>,
}

impl<DB: DatabaseLike> Roots<'_, DB> {
    /// Reads the `SELECT`s of `root` and of every query it nests.
    fn read(&mut self, root: Option<Cow<'_, Query>>) -> ControlFlow<LookupError> {
        let Some(root) = root else {
            return ControlFlow::Continue(());
        };
        let mut ctes = WithItems(Vec::new());
        let _ = walk(&*root, &mut ctes);
        let database = self.database;
        let found = &mut self.found;
        check_query_selects(database, &root, |_, scope, _, select| {
            found.extend(non_key_joins(database, scope, select, &ctes.0)?);
            Ok(())
        })
        .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Collects the folded names of the `WITH` items a query declares at any
/// depth.
struct WithItems(Vec<String>);

impl Visitor for WithItems {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        self.0.extend(
            query
                .with
                .iter()
                .flat_map(|with| &with.cte_tables)
                .map(|cte| {
                    normalize_identifier(
                        &cte.alias.name.value,
                        cte.alias.name.quote_style.is_some(),
                    )
                    .into_owned()
                }),
        );
        ControlFlow::Continue(())
    }
}

/// Whether `statement` is an `UPDATE` or `DELETE`, whose relations a query
/// rule reads as a `SELECT`.
fn modifies(statement: &Statement) -> bool {
    matches!(statement, Statement::Update(_) | Statement::Delete(_))
}

impl<DB: DatabaseLike> Visitor for Roots<'_, DB> {
    type Break = LookupError;

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<LookupError> {
        if modifies(statement) {
            if self.depth == 0 {
                self.read(root_query(statement))?;
            }
            self.depth += 1;
        }
        ControlFlow::Continue(())
    }

    fn post_visit_statement(&mut self, statement: &Statement) -> ControlFlow<LookupError> {
        if modifies(statement) {
            self.depth -= 1;
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        if self.depth == 0 {
            self.read(query_root(query))?;
        }
        // The scope of the query holding a `WITH` item reads no `SELECT` of
        // an `UPDATE` or `DELETE` the item runs.
        for item in query.with.iter().flat_map(|with| &with.cte_tables) {
            if let SetExpr::Update(statement) | SetExpr::Delete(statement) =
                item.query.body.as_ref()
            {
                self.read(statement_root(statement, query.with.as_ref()))?;
            }
        }
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }
}

/// Finds the joins whose columns cover a unique key of neither side.
struct NonKeyJoins;

impl ExpressionFinder for NonKeyJoins {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        let mut roots = Roots {
            database,
            depth: 0,
            found: Vec::new(),
        };
        if let ControlFlow::Break(error) = walk(node, &mut roots) {
            return Err(error);
        }
        Ok(roots.found)
    }

    fn problem(&self) -> &'static str {
        "whose columns cover a unique key of neither table, so a row of either side can pair with several rows of the other and the result holds pairs no stored row relates"
    }

    fn resolution(&self) -> &'static str {
        "Join on columns that cover a unique key of one table, such as a foreign key and the key it references, or allow the rule where every matching pair is meant."
    }
}

/// Struct defining a rule that reports an equality join between two catalog
/// tables whose equated columns cover a unique key of neither table.
///
/// Elmasri and Navathe, *Fundamentals of Database Systems*, 7th edition,
/// section 14.5.1, give the nonadditive join test for binary decompositions,
/// under which a join generates no spurious tuples exactly when its shared
/// attributes determine one side. Joined on columns that are a
/// key of neither, each row of one table pairs with every row of the other
/// holding the same values, as joining employees to projects on their
/// location pairs every employee with every project at that location. A
/// foreign key and the key it references pass, and so does any equality on
/// a unique key without one. A column the query fixes to one value, a
/// literal, a parameter or a column of an enclosing query, counts toward the
/// key. `EXISTS` and `IN` subqueries only filter, so their correlation is
/// not a join, and a CTE, derived table, view or function in `FROM` has no
/// key to cover. Equalities come from `ON`, `USING`, `NATURAL` and
/// `WHERE`. The rule reads views, materialized views, policies, SQL and
/// PL/pgSQL function bodies and, as a query rule, statements.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = JoinOnNonKeyColumns::default().into();
/// let schema = "CREATE TABLE projects (id INT PRIMARY KEY, location INT);
///     CREATE TABLE employees (id INT PRIMARY KEY, location INT, project_id INT REFERENCES projects (id));";
/// let by_location = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW v AS SELECT e.id FROM employees e JOIN projects p ON e.location = p.location;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&by_location).is_err());
/// let by_key = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW v AS SELECT e.id FROM employees e JOIN projects p ON e.project_id = p.id;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&by_key).is_ok());
/// ```
pub struct JoinOnNonKeyColumns<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for JoinOnNonKeyColumns<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<JoinOnNonKeyColumns<DB>> for GenericConstrainer<DB> {
    fn from(rule: JoinOnNonKeyColumns<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(JoinOnNonKeyColumns::default()));
        constrainer
    }
}

impl<DB> Rule for JoinOnNonKeyColumns<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(JoinOnNonKeyColumns),
            group: LintGroup::Pedantic,
            rationale: "A join whose columns are a key of neither table pairs each row of one side with every matching row of the other, generating tuples that no stored row relates.",
            source: Some("https://search.worldcat.org/isbn/9780133970777"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE employees (id BIGINT PRIMARY KEY, location BIGINT NOT NULL);\n\
CREATE TABLE projects (id BIGINT PRIMARY KEY, location BIGINT NOT NULL);\n\
CREATE VIEW employee_projects AS SELECT employees.id AS employee_id, projects.id AS project_id FROM employees JOIN projects ON employees.location = projects.location;",
                good: "CREATE TABLE projects (id BIGINT PRIMARY KEY);\n\
CREATE TABLE employees (id BIGINT PRIMARY KEY, project_id BIGINT NOT NULL REFERENCES projects (id));\n\
CREATE VIEW employee_projects AS SELECT employees.id AS employee_id, projects.id AS project_id FROM employees JOIN projects ON employees.project_id = projects.id;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for JoinOnNonKeyColumns<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&NonKeyJoins, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for JoinOnNonKeyColumns<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_statement(&NonKeyJoins, database, statement, reporter)
    }
}
