package trino_test

import data.trino
import data.trino_policies
import rego.v1

test_select_from_columns if {
	trino.allow with data.policies as trino_policies.policies
		with input as {
			"context": {
				"identity": {
					"user": "foo",
					"groups": ["some-group"],
				},
				"softwareStack": {"trinoVersion": "434"},
			},
			"action": {
				"operation": "SelectFromColumns",
				"resource": {"table": {
					"catalogName": "example_catalog",
					"schemaName": "example_schema",
					"tableName": "example_table",
					"columns": [
						"column1",
						"column2",
						"column3",
					],
				}},
			},
		}
}

test_rename_table if {
	trino.allow with data.policies as trino_policies.policies
		with input as {
			"context": {
				"identity": {
					"user": "foo",
					"groups": ["some-group"],
				},
				"softwareStack": {"trinoVersion": "434"},
			},
			"action": {
				"operation": "RenameTable",
				"resource": {"table": {
					"catalogName": "example_catalog",
					"schemaName": "example_schema",
					"tableName": "example_table",
				}},
				"targetResource": {"table": {
					"catalogName": "example_catalog",
					"schemaName": "example_schema",
					"tableName": "new_table_name",
				}},
			},
		}
}
