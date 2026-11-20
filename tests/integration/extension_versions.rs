//! Extensions created without `VERSION`, observed through
//! `extension_without_version`.

use sqlippy::prelude::*;

use super::common::findings;

#[test]
fn only_an_extension_created_without_version_is_reported() {
    assert_eq!(
        findings(
            ExtensionWithoutVersion::default(),
            Deployment::default(),
            "CREATE EXTENSION IF NOT EXISTS pgcrypto;
             CREATE EXTENSION citext VERSION '1.6';
             CREATE SCHEMA extensions;
             CREATE EXTENSION hstore WITH SCHEMA extensions VERSION '1.8';"
        ),
        [(
            "extension_without_version".to_owned(),
            Level::Warn,
            "pgcrypto".to_owned()
        )]
    );
}
