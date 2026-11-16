//! Shared request setting reads.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Counts duplicate keys across function bodies.
fn findings(schema: &str) -> usize {
    let database = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = RepeatedSettingRead::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer.set_rule_level("repeated_setting_read", Level::Warn);
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter(|error| matches!(error, Error::Violation(_)))
        .count()
}

#[test]
fn sql_and_plpgsql_read_the_same_key() {
    assert_eq!(
        findings(
            "CREATE FUNCTION first() RETURNS TEXT LANGUAGE sql AS $$ SELECT current_setting('app.user_id', true) $$; CREATE FUNCTION second() RETURNS TEXT LANGUAGE plpgsql AS $$ BEGIN RETURN current_setting('app.user_id', true); END $$;"
        ),
        1
    );
}

#[test]
fn absent_missing_ok_matches_false() {
    assert_eq!(
        findings(
            "CREATE FUNCTION first() RETURNS TEXT LANGUAGE sql AS $$ SELECT current_setting('app.user_id') $$; CREATE FUNCTION second() RETURNS TEXT LANGUAGE sql AS $$ SELECT current_setting('app.user_id', false) $$;"
        ),
        1
    );
}

#[test]
fn distinct_keys_and_flags_pass() {
    assert_eq!(
        findings(
            "CREATE FUNCTION first() RETURNS TEXT LANGUAGE sql AS $$ SELECT current_setting('app.user_id', true) $$; CREATE FUNCTION second() RETURNS TEXT LANGUAGE sql AS $$ SELECT current_setting('app.user_id', false) $$; CREATE FUNCTION third() RETURNS TEXT LANGUAGE sql AS $$ SELECT current_setting('app.other', true) $$;"
        ),
        0
    );
}

#[test]
fn one_function_and_policies_do_not_duplicate_a_key() {
    assert_eq!(
        findings(
            "CREATE FUNCTION first() RETURNS TEXT LANGUAGE sql AS $$ SELECT current_setting('app.user_id', true) || current_setting('app.user_id', true) $$; CREATE TABLE docs(owner TEXT); CREATE POLICY own ON docs USING(owner = current_setting('app.user_id', true));"
        ),
        0
    );
}

#[test]
fn dynamic_arguments_pass() {
    assert_eq!(
        findings(
            "CREATE FUNCTION first(key TEXT, missing BOOLEAN) RETURNS TEXT LANGUAGE sql AS $$ SELECT current_setting(key, true) || current_setting('app.user_id', missing) $$; CREATE FUNCTION second(key TEXT, missing BOOLEAN) RETURNS TEXT LANGUAGE sql AS $$ SELECT current_setting(key, true) || current_setting('app.user_id', missing) $$;"
        ),
        0
    );
}

#[test]
fn typed_accessor_passes() {
    assert_eq!(
        findings(
            "CREATE FUNCTION actor_id() RETURNS UUID LANGUAGE sql AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$; CREATE FUNCTION first() RETURNS UUID LANGUAGE sql AS $$ SELECT actor_id() $$; CREATE FUNCTION second() RETURNS UUID LANGUAGE sql AS $$ SELECT actor_id() $$;"
        ),
        0
    );
}

#[test]
fn uppercase_setting_names_match_lowercase_reads() {
    assert_eq!(
        findings(
            "CREATE FUNCTION first() RETURNS TEXT LANGUAGE sql
           AS $$ SELECT CURRENT_SETTING('app.user_id', true) $$;
         CREATE FUNCTION second() RETURNS TEXT LANGUAGE sql
           AS $$ SELECT PG_CATALOG.CURRENT_SETTING('app.user_id', true) $$;
         CREATE FUNCTION third() RETURNS TEXT LANGUAGE sql
           AS $$ SELECT current_setting('app.user_id', true) $$;"
        ),
        1
    );
}

#[test]
fn unsupported_setting_arity_is_not_a_shared_read() {
    assert_eq!(
        findings(
            "CREATE FUNCTION first() RETURNS TEXT LANGUAGE sql AS $$ SELECT current_setting('app.user_id', true, false) $$; CREATE FUNCTION second() RETURNS TEXT LANGUAGE sql AS $$ SELECT current_setting('app.user_id', true, false) $$;"
        ),
        0
    );
}

#[test]
fn unreadable_catalog_body_surfaces_a_lookup_error() {
    use std::sync::Arc;

    use pg_diesel::{PgDieselDatabase, dialect::PostgresDialect};
    use sql_traits::{
        structs::generic_db::GenericDBBuilder,
        traits::{DatabaseLike, FunctionLike},
    };

    let (_container, catalog) = crate::live_catalog::catalog(
        "public",
        "CREATE FUNCTION setting_reader() RETURNS TEXT LANGUAGE sql
         BEGIN ATOMIC SELECT current_setting('app.user_id', true); END;",
    );
    let function = catalog
        .functions()
        .find(|function| function.name() == "setting_reader")
        .unwrap();
    let metadata = catalog.function_metadata(function).unwrap().clone();
    let unreadable = function.clone().with_bound_definition(
        "CREATE FUNCTION setting_reader() RETURNS TEXT LANGUAGE sql BEGIN ATOMIC SELECT".into(),
    );
    let database: PgDieselDatabase = GenericDBBuilder::new("functions".into(), PostgresDialect)
        .add_function(Arc::new(unreadable), metadata)
        .into();
    let mut constrainer: GenericConstrainer<PgDieselDatabase> =
        RepeatedSettingRead::default().into();
    constrainer.set_deployment(Deployment::example());
    assert!(matches!(
        constrainer.validate_schema(&database),
        Err(Error::Lookup(
            sql_traits::errors::LookupError::FunctionBodyUnparsable { .. }
        ))
    ));
}
