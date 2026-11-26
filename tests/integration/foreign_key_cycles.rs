//! Foreign keys referencing one another in a cycle through distinct tables,
//! observed through `foreign_key_cycle`.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

/// Object and message of every `foreign_key_cycle` finding.
fn reported(sql: &str) -> Vec<(String, String)> {
    let constrainer: GenericConstrainer<ParserDB> = ForeignKeyCycle::default().into();
    findings(&constrainer, "foreign_key_cycle", sql)
        .into_iter()
        .map(|(_, object, message)| (object, message))
        .collect()
}

#[test]
fn a_cycle_closed_by_an_added_key_is_reported_on_the_first_table() {
    assert_eq!(
        reported(
            "CREATE TABLE parents (id BIGINT PRIMARY KEY, child_id BIGINT);
             CREATE TABLE children (id BIGINT PRIMARY KEY, parent_id BIGINT REFERENCES parents (id));
             ALTER TABLE parents ADD FOREIGN KEY (child_id) REFERENCES children (id);"
        ),
        [(
            "children".to_owned(),
            "Tables 'children' and 'parents' reference one another through the foreign key cycle `children(parent_id) -> parents(id) -> parents(child_id) -> children(id)`.".to_owned()
        )]
    );
}

#[test]
fn self_references_and_paths_that_do_not_return_are_not_cycles() {
    assert_eq!(
        reported(
            "CREATE TABLE nodes (id BIGINT PRIMARY KEY, parent_id BIGINT REFERENCES nodes (id));
             CREATE TABLE roots (id BIGINT PRIMARY KEY);
             CREATE TABLE lefts (id BIGINT PRIMARY KEY, root_id BIGINT REFERENCES roots (id));
             CREATE TABLE rights (id BIGINT PRIMARY KEY, root_id BIGINT REFERENCES roots (id));
             CREATE TABLE joins (
                 left_id BIGINT REFERENCES lefts (id),
                 right_id BIGINT REFERENCES rights (id),
                 root_id BIGINT REFERENCES roots (id)
             );"
        ),
        Vec::<(String, String)>::new()
    );
}

#[test]
fn deferrable_keys_still_close_a_cycle() {
    assert_eq!(
        reported(
            "CREATE TABLE parents (id BIGINT PRIMARY KEY, child_id BIGINT);
             CREATE TABLE children (id BIGINT PRIMARY KEY, parent_id BIGINT REFERENCES parents (id) DEFERRABLE INITIALLY DEFERRED);
             ALTER TABLE parents ADD FOREIGN KEY (child_id) REFERENCES children (id) DEFERRABLE INITIALLY DEFERRED;"
        )
        .len(),
        1
    );
}

#[test]
fn a_second_key_between_the_same_tables_is_listed_once() {
    assert_eq!(
        reported(
            "CREATE TABLE parents (id BIGINT PRIMARY KEY, child_id BIGINT, heir_id BIGINT);
             CREATE TABLE children (id BIGINT PRIMARY KEY, parent_id BIGINT REFERENCES parents (id));
             ALTER TABLE parents ADD FOREIGN KEY (child_id) REFERENCES children (id);
             ALTER TABLE parents ADD FOREIGN KEY (heir_id) REFERENCES children (id);"
        ),
        [(
            "children".to_owned(),
            "Tables 'children' and 'parents' reference one another through the foreign key cycle `children(parent_id) -> parents(id) -> parents(child_id) -> children(id)`. The foreign key `parents(heir_id) -> children(id)` also runs between these tables.".to_owned()
        )]
    );
}

#[test]
fn the_shortest_cycle_is_spelled_whatever_the_key_order() {
    assert_eq!(
        reported(
            "CREATE TABLE a (id INT PRIMARY KEY, b_id INT, c_id INT);
             CREATE TABLE b (id INT PRIMARY KEY, c_id INT);
             CREATE TABLE c (id INT PRIMARY KEY, a_id INT REFERENCES a (id));
             ALTER TABLE a ADD FOREIGN KEY (b_id) REFERENCES b (id);
             ALTER TABLE a ADD FOREIGN KEY (c_id) REFERENCES c (id);
             ALTER TABLE b ADD FOREIGN KEY (c_id) REFERENCES c (id);"
        ),
        [(
            "a".to_owned(),
            "Tables 'a', 'b' and 'c' reference one another through the foreign key cycle `a(c_id) -> c(id) -> c(a_id) -> a(id)`. The foreign keys `a(b_id) -> b(id)` and `b(c_id) -> c(id)` also run between these tables.".to_owned()
        )]
    );
}

#[test]
fn one_component_lists_its_other_keys_but_not_self_references_or_outside_tables() {
    assert_eq!(
        reported(
            "CREATE TABLE resources (id INT PRIMARY KEY, ownable_id INT, edge_id INT);
             CREATE TABLE resource_parents (
                 id INT PRIMARY KEY,
                 resource_id INT REFERENCES resources (id),
                 parent_id INT REFERENCES resources (id)
             );
             CREATE TABLE ownables (
                 id INT PRIMARY KEY,
                 resource_id INT REFERENCES resources (id),
                 project_id INT REFERENCES resources (id),
                 previous_id INT REFERENCES ownables (id)
             );
             CREATE TABLE grants (id INT PRIMARY KEY, resource_id INT REFERENCES resources (id));
             ALTER TABLE resources
                 ADD FOREIGN KEY (ownable_id) REFERENCES ownables (id),
                 ADD FOREIGN KEY (edge_id) REFERENCES resource_parents (id);"
        ),
        [(
            "ownables".to_owned(),
            "Tables 'ownables', 'resource_parents' and 'resources' reference one another through the foreign key cycle `ownables(resource_id) -> resources(id) -> resources(ownable_id) -> ownables(id)`. The foreign keys `ownables(project_id) -> resources(id)`, `resource_parents(resource_id) -> resources(id)`, `resource_parents(parent_id) -> resources(id)` and `resources(edge_id) -> resource_parents(id)` also run between these tables.".to_owned()
        )]
    );
}

#[test]
fn each_component_is_reported_once() {
    assert_eq!(
        reported(
            "CREATE TABLE a (id INT PRIMARY KEY, b_id INT);
             CREATE TABLE b (id INT PRIMARY KEY, a_id INT REFERENCES a (id));
             CREATE TABLE x (id INT PRIMARY KEY, y_id INT);
             CREATE TABLE y (id INT PRIMARY KEY, x_id INT REFERENCES x (id));
             CREATE TABLE z (id INT PRIMARY KEY, a_id INT REFERENCES a (id), x_id INT REFERENCES x (id));
             ALTER TABLE a ADD FOREIGN KEY (b_id) REFERENCES b (id);
             ALTER TABLE x ADD FOREIGN KEY (y_id) REFERENCES y (id);"
        )
        .into_iter()
        .map(|(object, _)| object)
        .collect::<Vec<_>>(),
        ["a", "x"]
    );
}
