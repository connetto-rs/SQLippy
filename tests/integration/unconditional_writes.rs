//! Write policies through which a client role writes every row.

use crate::common::{finding, findings, supabase};
use sqlippy::prelude::*;

const PROTECTED: &str =
    "CREATE TABLE docs (id INT, owner TEXT); ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

#[test]
fn a_write_policy_true_for_every_row_of_a_client_role_is_reported() {
    for policy in [
        "CREATE POLICY w ON docs FOR DELETE TO authenticated USING (true);",
        "CREATE POLICY w ON docs FOR UPDATE TO authenticated USING (true);",
        "CREATE POLICY w ON docs FOR INSERT TO authenticated WITH CHECK (true);",
        "CREATE POLICY w ON docs FOR INSERT TO authenticated WITH CHECK (1 = 1);",
        "CREATE POLICY w ON docs FOR ALL TO authenticated USING (true);",
        "CREATE POLICY w ON docs FOR DELETE USING (true);",
        "CREATE POLICY w ON docs FOR DELETE TO authenticated USING ((true));",
        "CREATE POLICY w ON docs FOR DELETE TO authenticated USING (true);
         CREATE POLICY r ON docs AS RESTRICTIVE FOR DELETE TO authenticated USING (true);",
    ] {
        assert_eq!(
            findings(
                UnconditionalClientWritePolicy::default(),
                supabase(),
                &format!("{PROTECTED}{policy}")
            ),
            [finding(
                "unconditional_client_write_policy",
                Level::Warn,
                "docs.w"
            )],
            "{policy}"
        );
    }
}

#[test]
fn a_row_dependent_or_read_only_or_restricted_policy_is_not_reported() {
    for policy in [
        "CREATE POLICY w ON docs FOR DELETE TO authenticated USING (owner = current_user);",
        "CREATE POLICY w ON docs FOR SELECT TO authenticated USING (true);",
        "CREATE POLICY w ON docs FOR DELETE TO reporting USING (true);",
        "CREATE POLICY w ON docs FOR UPDATE TO authenticated USING (owner = current_user) WITH CHECK (true);",
        "CREATE POLICY w ON docs FOR DELETE TO authenticated USING (true);
         CREATE POLICY r ON docs AS RESTRICTIVE FOR DELETE TO authenticated USING (owner = current_user);",
    ] {
        assert_eq!(
            findings(
                UnconditionalClientWritePolicy::default(),
                supabase(),
                &format!("{PROTECTED}{policy}")
            ),
            [],
            "{policy}"
        );
    }
}

#[test]
fn a_declared_credential_leaves_anonymous_writes_to_credential_free_write() {
    let sql = format!("{PROTECTED}CREATE POLICY w ON docs FOR DELETE TO anon USING (true);");
    assert_eq!(
        findings(UnconditionalClientWritePolicy::default(), supabase(), &sql),
        [finding(
            "unconditional_client_write_policy",
            Level::Warn,
            "docs.w"
        )]
    );
    assert_eq!(
        findings(
            UnconditionalClientWritePolicy::default(),
            supabase().with_credential("current_user").unwrap(),
            &sql
        ),
        []
    );
}
