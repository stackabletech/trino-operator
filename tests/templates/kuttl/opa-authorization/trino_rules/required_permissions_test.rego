package required_permissions_test

import data.trino
import rego.v1

policies := {
	"catalogs": [{"allow": "all"}],
	"schemas": [{"owner": true}],
	"tables": [{"privileges": [
		"SELECT",
		"INSERT",
		"DELETE",
		"UPDATE",
		"OWNERSHIP",
		"GRANT_SELECT",
	]}],
	"system_information": [{"allow": ["read", "write"]}],
}

test_access_catalog if {
	trino.allow with data.trino_policies.policies as policies
		with input as {
			"action": {
				"operation": "AccessCatalog",
				"resource": {"catalog": {"name": "system"}},
			},
			"context": {
				"identity": {
					"groups": [],
					"user": "admin",
				},
				"softwareStack": {"trinoVersion": "439"},
			},
		}
}

test_filter_catalogs if {
	trino.batch == {0, 1, 2, 3} with data.trino_policies.policies as policies
		with input as {
			"action": {
				"filterResources": [
					{"catalog": {"name": "tpcds"}},
					{"catalog": {"name": "system"}},
					{"catalog": {"name": "lakehouse"}},
					{"catalog": {"name": "tpch"}},
				],
				"operation": "FilterCatalogs",
			},
			"context": {
				"identity": {
					"groups": [],
					"user": "admin",
				},
				"softwareStack": {"trinoVersion": "439"},
			},
		}
}

test_filter_schemas if {
	trino.batch == {0, 1, 2, 3} with data.trino_policies.policies as policies
		with input as {
			"action": {
				"filterResources": [
					{"schema": {
						"catalogName": "system",
						"schemaName": "information_schema",
					}},
					{"schema": {
						"catalogName": "system",
						"schemaName": "runtime",
					}},
					{"schema": {
						"catalogName": "system",
						"schemaName": "metadata",
					}},
					{"schema": {
						"catalogName": "system",
						"schemaName": "jdbc",
					}},
				],
				"operation": "FilterSchemas",
			},
			"context": {
				"identity": {
					"groups": [],
					"user": "admin",
				},
				"softwareStack": {"trinoVersion": "439"},
			},
		}
}

no_resource_actions := {
	"ExecuteQuery",
	"ReadSystemInformation",
	"WriteSystemInformation",
}

test_no_resource_action if {
	every operation in no_resource_actions {
		trino.allow with data.trino_policies.policies as policies
			with input as {
				"action": {"operation": operation},
				"context": {
					"identity": {
						"groups": [],
						"user": "admin",
					},
					"softwareStack": {"trinoVersion": "439"},
				},
			}
	}
}

test_select_from_columns if {
	trino.allow with data.trino_policies.policies as policies
		with input as {
			"action": {
				"operation": "SelectFromColumns",
				"resource": {"table": {
					"catalogName": "system",
					"columns": ["schema_name"],
					"schemaName": "information_schema",
					"tableName": "schemata",
				}},
			},
			"context": {
				"identity": {
					"groups": [],
					"user": "admin",
				},
				"softwareStack": {"trinoVersion": "439"},
			},
		}
}

test_show_schemas if {
	trino.allow with data.trino_policies.policies as policies
		with input as {
			"action": {
				"operation": "ShowSchemas",
				"resource": {"catalog": {"name": "system"}},
			},
			"context": {
				"identity": {
					"groups": [],
					"user": "admin",
				},
				"softwareStack": {"trinoVersion": "439"},
			},
		}
}

table_resource_actions := {
	"AddColumn",
	"AlterColumn",
	"CreateView",
	"DeleteFromTable",
	"DropColumn",
	"DropMaterializedView",
	"DropTable",
	"DropView",
	"InsertIntoTable",
	"RefreshMaterializedView",
	"RenameColumn",
	"SetColumnComment",
	"SetTableComment",
	"SetViewComment",
	"ShowColumns",
	"ShowCreateTable",
	"TruncateTable",
}

test_table_resource_actions if {
	every operation in table_resource_actions {
		trino.allow with data.trino_policies.policies as policies
			with input as {
				"action": {
					"operation": operation,
					"resource": {"table": {
						"catalogName": "system",
						"schemaName": "information_schema",
						"tableName": "schemata",
					}},
				},
				"context": {
					"identity": {
						"groups": [],
						"user": "admin",
					},
					"softwareStack": {"trinoVersion": "439"},
				},
			}
	}
}
