package trino_column_mask_test

import data.trino_column_mask
import rego.v1

test_column_mask_with_matching_rule_and_environment if {
	policies := {"tables": [
		{
			"catalog": "non_matching_catalog",
			"columns": [{
				"name": "testcolumn",
				"mask": "testmask1",
				"mask_environment": {"user": "testuser1"},
			}],
		},
		{
			"schema": "non_matching_schema",
			"columns": [{
				"name": "testcolumn",
				"mask": "testmask2",
				"mask_environment": {"user": "testuser2"},
			}],
		},
		{
			"table": "non_matching_table",
			"columns": [{
				"name": "testcolumn",
				"mask": "testmask3",
				"mask_environment": {"user": "testuser3"},
			}],
		},
		{
			"catalog": "testcatalog",
			"schema": "testschema",
			"table": "testtable",
			"columns": [
				{
					"name": "non_matching_column1",
					"mask": "testmask4",
					"mask_environment": {"user": "testuser4"},
				},
				{
					"name": "testcolumn",
					"mask": "testmask5",
					"mask_environment": {"user": "testuser5"},
				},
				{
					"name": "non_matching_column2",
					"mask": "testmask6",
					"mask_environment": {"user": "testuser6"},
				},
			],
		},
		{"columns": [{
			"name": "testcolumn",
			"mask": "testmask7",
			"mask_environment": {"user": "testuser7"},
		}]},
	]}
	request := {
		"operation": "GetColumnMask",
		"resource": {"column": {
			"catalogName": "testcatalog",
			"schemaName": "testschema",
			"tableName": "testtable",
			"columnName": "testcolumn",
			"columnType": "testtype",
		}},
	}

	response := trino_column_mask.column_masks with input as request
		with data.trino_policies.policies as policies

	response == {{
		"expression": "testmask5",
		"identity": "testuser5",
	}}
}

test_column_mask_with_matching_rule_and_no_environment if {
	policies := {"tables": [
		{
			"catalog": "non_matching_catalog",
			"columns": [{
				"name": "testcolumn",
				"mask": "testmask1",
			}],
		},
		{
			"schema": "non_matching_schema",
			"columns": [{
				"name": "testcolumn",
				"mask": "testmask2",
			}],
		},
		{
			"table": "non_matching_table",
			"columns": [{
				"name": "testcolumn",
				"mask": "testmask3",
			}],
		},
		{
			"catalog": "testcatalog",
			"schema": "testschema",
			"table": "testtable",
			"columns": [
				{
					"name": "non_matching_column1",
					"mask": "testmask4",
				},
				{
					"name": "testcolumn",
					"mask": "testmask5",
				},
				{
					"name": "non_matching_column2",
					"mask": "testmask6",
				},
			],
		},
		{"columns": [{
			"name": "testcolumn",
			"mask": "testmask7",
		}]},
	]}
	request := {
		"operation": "GetColumnMask",
		"resource": {"column": {
			"catalogName": "testcatalog",
			"schemaName": "testschema",
			"tableName": "testtable",
			"columnName": "testcolumn",
			"columnType": "testtype",
		}},
	}

	response := trino_column_mask.column_masks with input as request
		with data.trino_policies.policies as policies

	response == {{"expression": "testmask5"}}
}

test_column_mask_with_matching_rule_and_no_column_constraints if {
	policies := {"tables": [
		# This is the first matching rule even if no column is defined.
		{
			"catalog": "testcatalog",
			"schema": "testschema",
			"table": "testtable",
		},
		{
			"catalog": "testcatalog",
			"schema": "testschema",
			"table": "testtable",
			"columns": [{
				"name": "testcolumn",
				"mask": "testmask",
			}],
		},
	]}
	request := {
		"operation": "GetColumnMask",
		"resource": {"column": {
			"catalogName": "testcatalog",
			"schemaName": "testschema",
			"tableName": "testtable",
			"columnName": "testcolumn",
			"columnType": "testtype",
		}},
	}

	response := trino_column_mask.column_masks with input as request
		with data.trino_policies.policies as policies

	response == set()
}

test_column_mask_with_no_matching_rule if {
	policies := {"tables": [
		{
			"catalog": "non_matching_catalog",
			"columns": [{
				"name": "testcolumn",
				"mask": "testmask1",
			}],
		},
		{
			"schema": "non_matching_schema",
			"columns": [{
				"name": "testcolumn",
				"mask": "testmask2",
			}],
		},
		{
			"table": "non_matching_table",
			"columns": [{
				"name": "testcolumn",
				"mask": "testmask3",
			}],
		},
		{"columns": [{
			"name": "testcolumn",
			"mask_environment": {"user": "testuser"},
		}]},
	]}
	request := {
		"operation": "GetColumnMask",
		"resource": {"column": {
			"catalogName": "testcatalog",
			"schemaName": "testschema",
			"tableName": "testtable",
			"columnName": "testcolumn",
			"columnType": "testtype",
		}},
	}

	response := trino_column_mask.column_masks with input as request
		with data.trino_policies.policies as policies

	response == set()
}

test_column_mask_with_no_rules if {
	policies := {}
	request := {
		"operation": "GetColumnMask",
		"resource": {"column": {
			"catalogName": "testcatalog",
			"schemaName": "testschema",
			"tableName": "testtable",
			"columnName": "testcolumn",
			"columnType": "testtype",
		}},
	}

	response := trino_column_mask.column_masks with input as request
		with data.trino_policies.policies as policies

	response == set()
}
