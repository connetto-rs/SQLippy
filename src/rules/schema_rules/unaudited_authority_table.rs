//! Submodule providing the `UnauditedAuthorityTable` rule.

use sql_traits::traits::{DatabaseLike, FunctionLike, TableLike, TriggerLike};
use sql_traits::utils::identifier_resolution::normalize_identifier;
use sqlparser::ast::{TriggerEvent, TriggerPeriod};

use crate::{
    deployment::{Declaration, WriteEvent},
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::authority_support::authority_columns,
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// Reports authority tables lacking declared audit coverage because permission changes need an audit trail.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
/// let mut constrainer: GenericConstrainer<ParserDB> = UnauditedAuthorityTable::default().into();
/// constrainer.set_deployment(Deployment::example());
/// constrainer.set_rule_level("unaudited_authority_table", Level::Deny);
/// let schema = "CREATE TABLE grants (user_id TEXT);
/// CREATE TABLE docs (id INT);
/// CREATE POLICY own ON docs USING (EXISTS (SELECT 1 FROM grants WHERE user_id = current_setting('app.user_id', true)));";
/// let bad = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&bad).is_err());
/// let good = ParserDB::parse::<PostgreSqlDialect>(&format!("{schema}
/// CREATE FUNCTION record_authority() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;
/// CREATE TRIGGER audit_grants AFTER INSERT OR UPDATE OR DELETE ON grants EXECUTE FUNCTION record_authority();")).unwrap();
/// assert!(constrainer.validate_schema(&good).is_ok());
/// ```
pub struct UnauditedAuthorityTable<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnauditedAuthorityTable<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnauditedAuthorityTable<DB>> for GenericConstrainer<DB> {
    fn from(rule: UnauditedAuthorityTable<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for UnauditedAuthorityTable<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(UnauditedAuthorityTable),
            group: LintGroup::Restriction,
            rationale: "Authority rows grant access, so changes need an audit trail covering every declared write event.",
            source: Some("https://www.postgresql.org/docs/17/trigger-definition.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE direct_grants (user_id TEXT, doc_id INT);
CREATE TABLE docs (id INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY readable ON docs USING (EXISTS (SELECT 1 FROM direct_grants g WHERE g.doc_id = docs.id AND g.user_id = current_setting('app.user_id', true)));",
                good: "CREATE TABLE direct_grants (user_id TEXT, doc_id INT);
CREATE TABLE docs (id INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY readable ON docs USING (EXISTS (SELECT 1 FROM direct_grants g WHERE g.doc_id = docs.id AND g.user_id = current_setting('app.user_id', true)));
CREATE TABLE authority_log (operation TEXT);
CREATE FUNCTION record_authority() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO authority_log VALUES (TG_OP); RETURN NULL; END $$;
CREATE TRIGGER audit_grants AFTER INSERT OR UPDATE OR DELETE ON direct_grants FOR EACH ROW EXECUTE FUNCTION record_authority();",
            },
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::AuditFunctions, Declaration::Credentials]
    }
}

/// Whether a trigger covers a declared write event.
fn covers_event(trigger: &TriggerEvent, event: WriteEvent) -> bool {
    match (trigger, event) {
        (TriggerEvent::Insert, WriteEvent::Insert) | (TriggerEvent::Delete, WriteEvent::Delete) => {
            true
        }
        (TriggerEvent::Update(columns), WriteEvent::Update) => columns.is_empty(),
        _ => false,
    }
}

impl<DB: DatabaseLike> SchemaRule for UnauditedAuthorityTable<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &DB,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        let subjects = authority_columns(database, reporter.deployment())?.subjects;
        for table in database.tables() {
            let identifier = database.table_id(table).unwrap();
            if !subjects.iter().any(|(subject, _)| *subject == identifier) {
                continue;
            }
            let mut audited = false;
            for (schema, name, events) in reporter.deployment().audit_functions() {
                audited = true;
                for event in events {
                    let covered = table.triggers(database)?.any(|trigger| {
                        if trigger.timing() != Some(TriggerPeriod::After) {
                            return false;
                        }
                        let Some(function) = trigger.function(database) else {
                            return false;
                        };
                        let target = function.target_name();
                        normalize_identifier(
                            target.schema().unwrap_or("public"),
                            target.schema_is_quoted(),
                        ) == schema
                            && function.stored_name() == name
                            && trigger
                                .events()
                                .iter()
                                .any(|trigger_event| covers_event(trigger_event, *event))
                    });
                    if !covered {
                        audited = false;
                        break;
                    }
                }
                if audited {
                    break;
                }
            }
            if !audited {
                let functions = reporter
                    .deployment()
                    .audit_functions()
                    .map(|(schema, name, _)| format!("{schema}.{name}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                reporter.table(table,
                    format!("Authority table '{}' lacks audit coverage for the declared events of function(s) '{functions}'.", table.table_name()),
                    "Attach AFTER triggers executing a declared audit function across all its declared events.".to_owned())?;
            }
        }
        Ok(())
    }
}
