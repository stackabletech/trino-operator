package trino_test

import data.trino
import data.trino_policies
import rego.v1

test_access_catalog if {
	trino.allow with input as {
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

test_no_resource_action if {
	every operation in {
		"ExecuteQuery",
		"ReadSystemInformation",
		"WriteSystemInformation",
	} {
		trino.allow with input as {
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

test_filter_catalogs if {
	trino.batch == {0, 1, 2, 3} with input as {
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
	trino.batch == {0, 1, 2, 3} with input as {
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

test_select_from_columns if {
	trino.allow with input as {
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
	trino.allow with input as {
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
