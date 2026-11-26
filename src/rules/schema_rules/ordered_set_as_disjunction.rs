//! Submodule providing the `OrderedSetAsDisjunction` rule.

use std::{collections::HashSet, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ExpressionContext, OperandType},
    traits::{DatabaseLike, FunctionLike, UserDefinedTypeLike},
};
use sqlparser::ast::{
    BinaryOperator, Delete, Expr, InTarget, JoinConstraint, JoinOperator, Select, Statement,
    TableFactor, TableWithJoins, UnaryOperator, Update, Visit, Visitor,
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::{CheckedRows, closed_set},
        literal_support::text_literal,
        not_in_support::null_extended,
        null_support::may_hold_null,
        policy_support::{conjuncts, unnested},
        type_support::user_type_named,
        typed_site_support::{TypedFinder, TypedFinding, check_typed_sites},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

schema_rule!(
    /// Struct defining a rule that reports a disjunction of equalities
    /// between two operands of one closed set that answers as `<`, `<=`, `>`
    /// or `>=` over an order of the set's labels.
    ///
    /// A closed set is an enum, whose order is the one it declares, or a
    /// text column a validated check restricts to a list of literals, which
    /// any order of the labels may fit. A check added `NOT VALID` closes no
    /// set, since rows stored before it may hold other labels. An operand is
    /// a column or a function parameter, and a text parameter takes the set
    /// of the operand it is compared with. The disjunction is built from
    /// `=`, `<>`, `[NOT] IN` over literals of the set, `AND`, `OR` and
    /// `NOT`, and holds an `OR`.
    /// It is evaluated for every pair of labels and must answer as the
    /// comparison does for each, a disjunction answering as `=` or `<>` not
    /// counting. The rule then evaluates the operands' `NULL` values, which a
    /// `NOT NULL` column and a parameter of a `STRICT` function never take
    /// and a top-level conjunct of `WHERE`, `ON`, `HAVING` or a policy reads
    /// as `FALSE`, and names the operands for which the comparison would
    /// change the result. The rule reads views, materialized views, policies
    /// and SQL and PL/pgSQL function bodies.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = OrderedSetAsDisjunction::default().into();
    /// let enumerated = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TYPE access_level AS ENUM ('read', 'write', 'admin');
    ///      CREATE FUNCTION sufficient(actual access_level, required access_level) RETURNS boolean
    ///          LANGUAGE sql IMMUTABLE STRICT
    ///          AS $$ SELECT actual = required OR (actual = 'write' AND required = 'read')
    ///                OR (actual = 'admin' AND required IN ('read', 'write')) $$;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&enumerated).is_err());
    /// let compared = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TYPE access_level AS ENUM ('read', 'write', 'admin');
    ///      CREATE FUNCTION sufficient(actual access_level, required access_level) RETURNS boolean
    ///          LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT actual >= required $$;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&compared).is_ok());
    /// ```
    OrderedSetAsDisjunction,
    LintGroup::Pedantic,
    "Equalities listing the pairs an order admits repeat the order by hand, and a label added to the set falls outside every case.",
    Some("https://www.postgresql.org/docs/current/datatype-enum.html#DATATYPE-ENUM-ORDERING"),
    RuleExample {
        bad: "CREATE TYPE access_level AS ENUM ('read', 'write', 'admin');\n\
CREATE FUNCTION sufficient(actual access_level, required access_level) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$ SELECT actual = required OR (actual = 'write' AND required = 'read') OR (actual = 'admin' AND required IN ('read', 'write')) $$;",
        good: "CREATE TYPE access_level AS ENUM ('read', 'write', 'admin');\n\
CREATE FUNCTION sufficient(actual access_level, required access_level) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$ SELECT actual >= required $$;",
    }
);

/// The labels of a closed set.
#[derive(Clone, PartialEq)]
struct Domain {
    /// The labels, in the order the enum declares or the check lists.
    labels: Vec<String>,
    /// The enum type declaring the order, or `None` for a checked text
    /// column, whose labels any order may fit.
    declared: Option<String>,
}

/// One operand of a disjunction.
struct Operand {
    /// The operand as written.
    written: String,
    /// The set the operand ranges over, inferred later for a text parameter.
    domain: Option<Domain>,
    /// Whether the operand can be `NULL`.
    nullable: bool,
}

/// A disjunction over the operands, which `Formula::Same` and
/// `Formula::Listed` index.
enum Formula<'e> {
    /// `OR` of the operands.
    Any(Vec<Formula<'e>>),
    /// `AND` of the operands.
    All(Vec<Formula<'e>>),
    /// `NOT` of the operand.
    Not(Box<Formula<'e>>),
    /// Two operands are equal.
    Same(usize, usize),
    /// An operand equals one of the literals.
    Listed(usize, Vec<&'e str>),
}

impl Formula<'_> {
    /// The three-valued answer for the operands taking `values`, `None`
    /// standing for `NULL`, with every literal already a label index of
    /// `labels`.
    fn evaluate(&self, values: &[Option<usize>], labels: &[String]) -> Option<bool> {
        match self {
            Self::Any(operands) => {
                let mut answer = Some(false);
                for operand in operands {
                    match operand.evaluate(values, labels) {
                        Some(true) => return Some(true),
                        None => answer = None,
                        Some(false) => {}
                    }
                }
                answer
            }
            Self::All(operands) => {
                let mut answer = Some(true);
                for operand in operands {
                    match operand.evaluate(values, labels) {
                        Some(false) => return Some(false),
                        None => answer = None,
                        Some(true) => {}
                    }
                }
                answer
            }
            Self::Not(operand) => operand.evaluate(values, labels).map(|answer| !answer),
            Self::Same(left, right) => Some(values[*left]? == values[*right]?),
            Self::Listed(operand, literals) => {
                let label = &labels[values[*operand]?];
                Some(literals.iter().any(|literal| literal == label))
            }
        }
    }

    /// Every literal the formula writes.
    fn literals(&self) -> Vec<&str> {
        match self {
            Self::Any(operands) | Self::All(operands) => {
                operands.iter().flat_map(Self::literals).collect()
            }
            Self::Not(operand) => operand.literals(),
            Self::Same(..) => Vec::new(),
            Self::Listed(_, literals) => literals.clone(),
        }
    }

    /// Every pair of operands an equality joins.
    fn pairs(&self) -> Vec<(usize, usize)> {
        match self {
            Self::Any(operands) | Self::All(operands) => {
                operands.iter().flat_map(Self::pairs).collect()
            }
            Self::Not(operand) => operand.pairs(),
            Self::Same(left, right) => vec![(*left, *right)],
            Self::Listed(..) => Vec::new(),
        }
    }
}

/// An order comparison a disjunction answers as.
struct Comparison {
    /// The comparison, written over the operands.
    written: String,
    /// The labels in ascending order.
    order: Vec<String>,
}

/// An order comparison and whether it holds between two label positions.
type Operator = (&'static str, fn(usize, usize) -> bool);

/// The comparison of declared labels whose answer for each pair of label
/// positions `relation` holds.
fn declared_comparison(relation: &[Vec<bool>]) -> Option<&'static str> {
    let operators: [Operator; 4] = [
        (">=", |left, right| left >= right),
        ("<=", |left, right| left <= right),
        (">", |left, right| left > right),
        ("<", |left, right| left < right),
    ];
    operators.into_iter().find_map(|(operator, holds)| {
        relation
            .iter()
            .enumerate()
            .all(|(left, row)| {
                row.iter()
                    .enumerate()
                    .all(|(right, &answer)| answer == holds(left, right))
            })
            .then_some(operator)
    })
}

/// The ascending order of label indices under which `relation` answers as
/// `>=`, or as `>` when it holds no label against itself.
fn fitted_order(relation: &[Vec<bool>]) -> Option<(Vec<usize>, &'static str)> {
    let reflexive = relation.iter().enumerate().all(|(label, row)| row[label]);
    let irreflexive = relation.iter().enumerate().all(|(label, row)| !row[label]);
    if !reflexive && !irreflexive {
        return None;
    }
    for (left, row) in relation.iter().enumerate() {
        for right in left + 1..relation.len() {
            if row[right] == relation[right][left] {
                return None;
            }
        }
    }
    // A complete antisymmetric relation is transitive exactly when no two
    // labels hold against the same number of labels.
    let ranks: Vec<usize> = relation
        .iter()
        .map(|row| row.iter().filter(|&&answer| answer).count())
        .collect();
    let mut order: Vec<usize> = (0..relation.len()).collect();
    order.sort_by_key(|&label| ranks[label]);
    if order
        .windows(2)
        .any(|pair| ranks[pair[0]] == ranks[pair[1]])
    {
        return None;
    }
    Some((order, if reflexive { ">=" } else { ">" }))
}

/// The enum type `expression` takes and its labels in declared order.
fn declared_domain<DB: DatabaseLike>(
    database: &DB,
    context: &ExpressionContext<'_, '_, DB>,
    expression: &Expr,
) -> Result<Option<Domain>, LookupError> {
    let OperandType::Known { type_name, .. } = context.type_of(expression)? else {
        return Ok(None);
    };
    let Some(user_type) = user_type_named(database, &type_name) else {
        return Ok(None);
    };
    Ok(user_type.enumeration().map(|enumeration| Domain {
        labels: enumeration
            .into_members()
            .map(|member| member.label().to_owned())
            .collect(),
        declared: Some(user_type.name().to_owned()),
    }))
}

/// Builds the formula of a disjunction, registering its operands.
struct Builder<'c, 'q, 'db, DB: DatabaseLike> {
    database: &'db DB,
    context: &'c ExpressionContext<'q, 'db, DB>,
    /// The `FROM` items an outer join pads with `NULL`, in the queries met
    /// so far.
    null_extended: &'c HashSet<*const TableFactor>,
    operands: Vec<Operand>,
}

impl<DB: DatabaseLike> Builder<'_, '_, '_, DB> {
    /// The index of the operand `expression` writes, registered on first
    /// sight, or `None` when it is no column or parameter of a closed set.
    fn operand(&mut self, expression: &Expr) -> Result<Option<usize>, LookupError> {
        let expression = unnested(expression);
        if !matches!(
            expression,
            Expr::Identifier(_) | Expr::CompoundIdentifier(_)
        ) {
            return Ok(None);
        }
        let written = expression.to_string();
        if let Some(index) = self
            .operands
            .iter()
            .position(|operand| operand.written == written)
        {
            return Ok(Some(index));
        }
        let declared = declared_domain(self.database, self.context, expression)?;
        let operand = match self.context.reference(expression)? {
            Some((
                ColumnDefinition::Base {
                    column, database, ..
                },
                binding,
            )) => {
                let domain = match declared {
                    Some(domain) => Some(domain),
                    None => {
                        closed_set(database, column, CheckedRows::Stored)?.map(|labels| Domain {
                            labels: labels.into_iter().map(str::to_owned).collect(),
                            declared: None,
                        })
                    }
                };
                let Some(domain) = domain else {
                    return Ok(None);
                };
                let extended = binding.entry().is_some_and(|entry| {
                    self.null_extended
                        .contains(&std::ptr::from_ref(entry.factor()))
                });
                Operand {
                    written,
                    domain: Some(domain),
                    nullable: extended || may_hold_null(database, column)?,
                }
            }
            Some((ColumnDefinition::Parameter { function, ordinal }, _)) => Operand {
                written,
                domain: declared,
                nullable: !function.returns_null_on_null_argument(self.database, ordinal),
            },
            _ => return Ok(None),
        };
        self.operands.push(operand);
        Ok(Some(self.operands.len() - 1))
    }

    /// The equality of `left` and `right`, an operand with an operand or
    /// with a text literal in either order.
    fn equality<'e>(
        &mut self,
        left: &'e Expr,
        right: &'e Expr,
    ) -> Result<Option<Formula<'e>>, LookupError> {
        if let Some(literal) = text_literal(right) {
            return Ok(self
                .operand(left)?
                .map(|operand| Formula::Listed(operand, vec![literal])));
        }
        if let Some(literal) = text_literal(left) {
            return Ok(self
                .operand(right)?
                .map(|operand| Formula::Listed(operand, vec![literal])));
        }
        let (Some(left), Some(right)) = (self.operand(left)?, self.operand(right)?) else {
            return Ok(None);
        };
        Ok(Some(Formula::Same(left, right)))
    }

    /// The formula `expression` writes, or `None` when a part of it is
    /// outside the shapes read.
    fn formula<'e>(&mut self, expression: &'e Expr) -> Result<Option<Formula<'e>>, LookupError> {
        Ok(match expression {
            Expr::Nested(inner) => self.formula(inner)?,
            Expr::BinaryOp {
                left,
                op: op @ (BinaryOperator::Or | BinaryOperator::And),
                right,
            } => {
                let (Some(left), Some(right)) = (self.formula(left)?, self.formula(right)?) else {
                    return Ok(None);
                };
                let mut operands = Vec::new();
                for operand in [left, right] {
                    match (op, operand) {
                        (BinaryOperator::Or, Formula::Any(inner))
                        | (BinaryOperator::And, Formula::All(inner)) => operands.extend(inner),
                        (_, operand) => operands.push(operand),
                    }
                }
                Some(if *op == BinaryOperator::Or {
                    Formula::Any(operands)
                } else {
                    Formula::All(operands)
                })
            }
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr,
            } => self
                .formula(expr)?
                .map(|inner| Formula::Not(Box::new(inner))),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => self.equality(left, right)?,
            Expr::BinaryOp {
                left,
                op: BinaryOperator::NotEq,
                right,
            } => self
                .equality(left, right)?
                .map(|inner| Formula::Not(Box::new(inner))),
            Expr::In {
                expr,
                target: InTarget::List(list),
                negated,
                ..
            } => {
                let Some(literals) = list.iter().map(text_literal).collect::<Option<Vec<_>>>()
                else {
                    return Ok(None);
                };
                let Some(operand) = self.operand(expr)? else {
                    return Ok(None);
                };
                let listed = Formula::Listed(operand, literals);
                Some(if *negated {
                    Formula::Not(Box::new(listed))
                } else {
                    listed
                })
            }
            _ => None,
        })
    }
}

/// Gives each operand without a set the set of an operand it is compared
/// with, and returns the one set every operand shares.
fn shared_domain(operands: &mut [Operand], pairs: &[(usize, usize)]) -> Option<Domain> {
    loop {
        let mut changed = false;
        for &(left, right) in pairs {
            for (from, to) in [(left, right), (right, left)] {
                if operands[to].domain.is_none()
                    && let Some(domain) = operands[from].domain.clone()
                {
                    operands[to].domain = Some(domain);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let domain = operands.first()?.domain.clone()?;
    operands
        .iter()
        .all(|operand| operand.domain.as_ref() == Some(&domain))
        .then_some(domain)
}

/// The labels of `domain` written in single quotes and joined by `joint`.
fn quoted(labels: impl IntoIterator<Item = impl AsRef<str>>, joint: &str) -> String {
    labels
        .into_iter()
        .map(|label| format!("'{}'", label.as_ref().replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(joint)
}

/// Collects the disjunctions that answer as an order comparison.
struct Disjunctions<'c, 'q, 'db, DB: DatabaseLike> {
    database: &'db DB,
    context: &'c ExpressionContext<'q, 'db, DB>,
    /// Whether the first expression visited is a filter whose top-level
    /// conjuncts read `NULL` as `FALSE`.
    root_filter: bool,
    /// The top-level conjuncts of the filters met so far.
    filters: HashSet<*const Expr>,
    /// The `FROM` items an outer join pads with `NULL`, in the queries met
    /// so far.
    null_extended: HashSet<*const TableFactor>,
    /// The disjunctions inside a reported one.
    read: HashSet<*const Expr>,
    found: Vec<TypedFinding>,
}

impl<DB: DatabaseLike> Disjunctions<'_, '_, '_, DB> {
    /// Records the top-level conjuncts of `filter`.
    fn filter(&mut self, filter: &Expr) {
        self.filters
            .extend(conjuncts(filter).into_iter().map(std::ptr::from_ref));
    }

    /// Marks every disjunction under `expression` as read.
    fn mark(&mut self, expression: &Expr) {
        match expression {
            Expr::Nested(inner) | Expr::UnaryOp { expr: inner, .. } => self.mark(inner),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or | BinaryOperator::And,
                right,
            } => {
                self.read.insert(std::ptr::from_ref(expression));
                self.mark(left);
                self.mark(right);
            }
            _ => {}
        }
    }

    /// The finding of the disjunction `expression`, when it answers as an
    /// order comparison.
    fn judge(&mut self, expression: &Expr) -> Result<Option<TypedFinding>, LookupError> {
        let mut builder = Builder {
            database: self.database,
            context: self.context,
            null_extended: &self.null_extended,
            operands: Vec::new(),
        };
        let Some(formula) = builder.formula(expression)? else {
            return Ok(None);
        };
        let mut operands = builder.operands;
        if operands.len() != 2 {
            return Ok(None);
        }
        let Some(domain) = shared_domain(&mut operands, &formula.pairs()) else {
            return Ok(None);
        };
        if domain.labels.len() < 2
            || formula
                .literals()
                .iter()
                .any(|literal| !domain.labels.iter().any(|label| label == literal))
        {
            return Ok(None);
        }
        let labels = &domain.labels;
        // Without a NULL operand every answer is TRUE or FALSE.
        let relation: Vec<Vec<bool>> = (0..labels.len())
            .map(|left| {
                (0..labels.len())
                    .map(|right| formula.evaluate(&[Some(left), Some(right)], labels) == Some(true))
                    .collect()
            })
            .collect();
        let (left, right) = (&operands[0].written, &operands[1].written);
        let comparison = match &domain.declared {
            Some(_) => declared_comparison(&relation).map(|operator| Comparison {
                written: format!("{left} {operator} {right}"),
                order: labels.clone(),
            }),
            None => fitted_order(&relation).map(|(order, operator)| Comparison {
                written: format!("{left} {operator} {right}"),
                order: order
                    .into_iter()
                    .map(|label| labels[label].clone())
                    .collect(),
            }),
        };
        let Some(comparison) = comparison else {
            return Ok(None);
        };
        let filter = self.filters.contains(&std::ptr::from_ref(expression));
        let changed = changed_by_null(&formula, &operands, filter, labels);
        let order = quoted(&comparison.order, " < ");
        let mut resolution = match (Engine::of(self.database), &domain.declared) {
            (Engine::Sqlite, _) => format!(
                "Map both operands to integer ranks with `CASE` in the order {order}, preserving NULL, and apply `{}` to those ranks.",
                comparison.written
            ),
            (Engine::PostgreSql, Some(type_name)) => format!(
                "Write `{}`, which reads the order enum '{type_name}' declares.",
                comparison.written
            ),
            (Engine::PostgreSql, None) => format!(
                "Declare the set as `CREATE TYPE ... AS ENUM ({})`, type both operands with it and write `{}`.",
                quoted(&comparison.order, ", "),
                comparison.written
            ),
        };
        if !changed.is_empty() {
            let required = match Engine::of(self.database) {
                Engine::PostgreSql => "declare the function STRICT or the column NOT NULL",
                Engine::Sqlite => "declare the column NOT NULL",
            };
            resolution = format!(
                "{resolution} The comparison answers NULL where the disjunction does not when {} is NULL, so {required} first.",
                changed
                    .iter()
                    .map(|operand| format!("'{operand}'"))
                    .collect::<Vec<_>>()
                    .join(" or ")
            );
        }
        self.mark(expression);
        Ok(Some(TypedFinding {
            found: format!(
                "`{expression}`, which answers as `{}` over the order {order}",
                comparison.written
            ),
            resolution,
        }))
    }
}
/// Every `FROM` item `joined` holds, those of nested joins included.
fn factors(joined: &TableWithJoins) -> Vec<&TableFactor> {
    let mut found = Vec::new();
    for factor in
        std::iter::once(&joined.relation).chain(joined.joins.iter().map(|join| &join.relation))
    {
        match factor {
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => found.extend(factors(table_with_joins)),
            _ => found.push(factor),
        }
    }
    found
}

/// The operands whose `NULL` makes the disjunction `formula` answer
/// otherwise than the comparison, which answers `NULL`, a filter reading
/// `NULL` as `FALSE`.
fn changed_by_null<'o>(
    formula: &Formula<'_>,
    operands: &'o [Operand],
    filter: bool,
    labels: &[String],
) -> Vec<&'o str> {
    let values = |operand: &Operand| -> Vec<Option<usize>> {
        let mut values: Vec<Option<usize>> = (0..labels.len()).map(Some).collect();
        if operand.nullable {
            values.push(None);
        }
        values
    };
    let mut changed = Vec::new();
    for (index, operand) in operands.iter().enumerate() {
        if !operand.nullable {
            continue;
        }
        let other = &operands[1 - index];
        let differs = values(other).into_iter().any(|value| {
            let mut assignment = [None, None];
            assignment[1 - index] = value;
            let answer = formula.evaluate(&assignment, labels);
            if filter {
                answer == Some(true)
            } else {
                answer.is_some()
            }
        });
        if differs {
            changed.push(operand.written.as_str());
        }
    }
    changed
}

impl<DB: DatabaseLike> Visitor for Disjunctions<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<LookupError> {
        for filter in select.selection.iter().chain(&select.having) {
            self.filter(filter);
        }
        for joined in &select.from {
            for factor in factors(joined) {
                if null_extended(joined, factor, false) {
                    self.null_extended.insert(std::ptr::from_ref(factor));
                }
            }
        }
        for join in select.from.iter().flat_map(|from| &from.joins) {
            if let JoinOperator::Join(JoinConstraint::On(condition))
            | JoinOperator::Inner(JoinConstraint::On(condition))
            | JoinOperator::Left(JoinConstraint::On(condition))
            | JoinOperator::LeftOuter(JoinConstraint::On(condition))
            | JoinOperator::Right(JoinConstraint::On(condition))
            | JoinOperator::RightOuter(JoinConstraint::On(condition))
            | JoinOperator::FullOuter(JoinConstraint::On(condition)) = &join.join_operator
            {
                self.filter(condition);
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<LookupError> {
        if let Statement::Update(Update {
            selection: Some(filter),
            ..
        })
        | Statement::Delete(Delete {
            selection: Some(filter),
            ..
        }) = statement
        {
            self.filter(filter);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        if self.root_filter {
            self.root_filter = false;
            self.filter(expression);
        }
        if !matches!(
            expression,
            Expr::BinaryOp {
                op: BinaryOperator::Or,
                ..
            }
        ) || self.read.contains(&std::ptr::from_ref(expression))
        {
            return ControlFlow::Continue(());
        }
        match self.judge(expression) {
            Ok(Some(finding)) => self.found.push(finding),
            Ok(None) => {}
            Err(error) => return ControlFlow::Break(error),
        }
        ControlFlow::Continue(())
    }
}

/// Finds and explains disjunctions answering as order comparisons.
struct Finder;

impl TypedFinder for Finder {
    fn reads_checks(&self) -> bool {
        false
    }

    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        context: &ExpressionContext<'_, '_, DB>,
        node: &V,
        clause: bool,
    ) -> Result<Vec<TypedFinding>, LookupError> {
        let mut disjunctions = Disjunctions {
            database,
            context,
            root_filter: clause,
            filters: HashSet::new(),
            null_extended: HashSet::new(),
            read: HashSet::new(),
            found: Vec::new(),
        };
        if let ControlFlow::Break(error) = walk(node, &mut disjunctions) {
            return Err(error);
        }
        Ok(disjunctions.found)
    }

    fn problem(&self) -> &'static str {
        "so the order of the set is written out case by case and a label added to the set falls outside every case"
    }
}

impl<DB: DatabaseLike> SchemaRule for OrderedSetAsDisjunction<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_typed_sites(&Finder, database, reporter)
    }
}
