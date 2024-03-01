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
	"catalog_session_properties": [{"allow": true}],
	"system_session_properties": [{"allow": true}],
	"impersonation": [{"new_user": ".*"}],
	"authorization": [{"new_user": ".*"}],
	"functions": [{"privileges": [
		"EXECUTE",
		"GRANT_EXECUTE",
		"OWNERSHIP",
	]}],
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

test_create_schema if {
	trino.allow with data.trino_policies.policies as policies
		with input as {
			"action": {
				"operation": "CreateSchema",
				"resource": {"schema": {
					"catalogName": "my_catalog",
					"schemaName": "my_schema",
					"properties": {},
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

test_filter_columns if {
	trino.batch == {0, 1} with data.trino_policies.policies as policies
		with input as {
			"action": {
				"filterResources": [{"table": {
					"catalogName": "my_catalog",
					"schemaName": "my_schema",
					"tableName": "my_table",
					"columns": ["column_one", "column_two"],
				}}],
				"operation": "FilterColumns",
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

test_filter_functions if {
	trino.batch == {0, 1} with data.trino_policies.policies as policies
		with input as {
			"action": {
				"filterResources": [
					{"function": {
						"catalogName": "my_catalog",
						"schemaName": "my_schema",
						"functionName": "function_one",
					}},
					{"function": {
						"catalogName": "my_catalog",
						"schemaName": "my_schema",
						"functionName": "function_two",
					}},
				],
				"operation": "FilterFunctions",
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

test_filter_view_query_owned_by if {
	trino.batch == {0, 1} with data.trino_policies.policies as policies
		with input as {
			"action": {
				"filterResources": [
					{"user": {
						"user": "user_one",
						"groups": [],
					}},
					{"user": {
						"user": "user_two",
						"groups": [],
					}},
				],
				"operation": "FilterViewQueryOwnedBy",
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

function_resource_actions := {
	"ExecuteProcedure",
	"CreateFunction",
	"DropFunction",
	"ExecuteFunction",
	"CreateViewWithExecuteFunction",
}

test_function_resource_actions if {
	every operation in function_resource_actions {
		trino.allow with data.trino_policies.policies as policies
			with input as {
				"action": {
					"operation": operation,
					"resource": {"function": {
						"catalogName": "my_catalog",
						"schemaName": "my_schema",
						"functionName": "my_function",
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

test_execute_table_procedure if {
	trino.allow with data.trino_policies.policies as policies
		with input as {
			"action": {
				"operation": "ExecuteTableProcedure",
				"resource": {
					"table": {
						"catalogName": "my_catalog",
						"schemaName": "my_schema",
						"tableName": "my_table",
					},
					"function": {"functionName": "my_procedure"},
				},
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

column_operations_on_table_like_objects := {
	"CreateViewWithSelectFromColumns",
	"SelectFromColumns",
	"UpdateTableColumns",
}

test_column_operations_on_table_like_objects if {
	every operation in column_operations_on_table_like_objects {
		trino.allow with data.trino_policies.policies as policies
			with input as {
				"action": {
					"operation": operation,
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

rename_table_like_object_actions := {
	"RenameMaterializedView",
	"RenameTable",
	"RenameView",
}

test_rename_table_like_object if {
	every operation in rename_table_like_object_actions {
		trino.allow with data.trino_policies.policies as policies
			with input as {
				"action": {
					"operation": operation,
					"resource": {"table": {
						"catalogName": "my_catalog",
						"schemaName": "my_schema",
						"tableName": "my_table",
					}},
					"targetResource": {"table": {
						"catalogName": "my_catalog",
						"schemaName": "new_schema_name",
						"tableName": "new_table_name",
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

test_rename_schema if {
	trino.allow with data.trino_policies.policies as policies
		with input as {
			"action": {
				"operation": "RenameSchema",
				"resource": {"schema": {
					"catalogName": "my_catalog",
					"schemaName": "my_schema",
				}},
				"targetResource": {"schema": {
					"catalogName": "my_catalog",
					"schemaName": "new_schema_name",
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

test_set_catalog_session_properties if {
	trino.allow with data.trino_policies.policies as policies
		with input as {
			"action": {
				"operation": "SetCatalogSessionProperty",
				"resource": {"catalogSessionProperty": {
					"catalogName": "my_catalog",
					"propertyName": "my_property",
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

test_set_system_session_properties if {
	trino.allow with data.trino_policies.policies as policies
		with input as {
			"action": {
				"operation": "SetSystemSessionProperty",
				"resource": {"systemSessionProperty": {"name": "resource_name"}},
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

test_set_schema_authorization if {
	trino.allow with data.trino_policies.policies as policies
		with input as {
			"action": {
				"operation": "SetSchemaAuthorization",
				"resource": {"schema": {
					"catalogName": "my_catalog",
					"schemaName": "my_schema",
				}},
				"grantee": {
					"name": "user",
					"type": "my_user",
				},
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

set_authorization_on_table_like_object_actions := {
	"SetTableAuthorization",
	"SetViewAuthorization",
}

test_set_authorization_on_table_like_object if {
	every operation in set_authorization_on_table_like_object_actions {
		trino.allow with data.trino_policies.policies as policies
			with input as {
				"action": {
					"operation": operation,
					"resource": {"table": {
						"catalogName": "my_catalog",
						"schemaName": "my_schema",
						"tableName": "my_table",
					}},
					"grantee": {
						"name": "user",
						"type": "my_user",
					},
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

test_impersonate_user if {
	trino.allow with data.trino_policies.policies as policies
		with input as {
			"action": {
				"operation": "ImpersonateUser",
				"resource": {"user": {"user": "testuser"}},
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
