package required_permissions_test

import data.trino
import rego.v1

policies := {
	"catalogs": [{"allow": "all"}],
	"queries": [{"allow": {"execute", "kill", "view"}}],
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

test_filter_tables if {
	trino.batch == {0, 1, 2, 3, 4, 5, 6, 7} with data.trino_policies.policies as policies
		with input as {
			"action": {
				"filterResources": [
					{"table": {
						"catalogName": "lakehouse",
						"schemaName": "sf1",
						"tableName": "customer",
					}},
					{"table": {
						"catalogName": "lakehouse",
						"schemaName": "sf1",
						"tableName": "orders",
					}},
					{"table": {
						"catalogName": "lakehouse",
						"schemaName": "sf1",
						"tableName": "lineitem",
					}},
					{"table": {
						"catalogName": "lakehouse",
						"schemaName": "sf1",
						"tableName": "part",
					}},
					{"table": {
						"catalogName": "lakehouse",
						"schemaName": "sf1",
						"tableName": "partsupp",
					}},
					{"table": {
						"catalogName": "lakehouse",
						"schemaName": "sf1",
						"tableName": "supplier",
					}},
					{"table": {
						"catalogName": "lakehouse",
						"schemaName": "sf1",
						"tableName": "nation",
					}},
					{"table": {
						"catalogName": "lakehouse",
						"schemaName": "sf1",
						"tableName": "region",
					}},
				],
				"operation": "FilterTables",
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

table_with_properties_actions := {
	"CreateMaterializedView",
	"CreateTable",
	"SetMaterializedViewProperties",
	"SetTableProperties",
}

test_table_with_properties_actions if {
	every operation in table_with_properties_actions {
		trino.allow with data.trino_policies.policies as policies
			with input as {
				"action": {
					"operation": operation,
					"resource": {"table": {
						"catalogName": "system",
						"schemaName": "information_schema",
						"tableName": "schemata",
						"properties": {
							"string_item": "string_value",
							"empty_item": null,
							"boxed_number_item": 32,
						},
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

identity_resource_actions := {
	"KillQueryOwnedBy",
	"ViewQueryOwnedBy",
}

test_identity_resource_actions if {
	every operation in identity_resource_actions {
		trino.allow with data.trino_policies.policies as policies
			with input as {
				"action": {
					"operation": operation,
					"resource": {"user": {
						"user": "dummy-user",
						"groups": ["some_group"],
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

schema_resource_actions := {
	"DropSchema",
	"ShowCreateSchema",
	"ShowFunctions",
	"ShowTables",
}

test_schema_resource_actions if {
	every operation in schema_resource_actions {
		trino.allow with data.trino_policies.policies as policies
			with input as {
				"action": {
					"operation": operation,
					"resource": {"schema": {
						"catalogName": "system",
						"schemaName": "information_schema",
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
