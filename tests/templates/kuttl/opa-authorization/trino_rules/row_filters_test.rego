package trino_row_filters_test

import data.trino_row_filters
import rego.v1

test_row_filters_with_matching_rule_and_environment if {
	policies := {"tables": [
		{
			"catalog": "non_matching_catalog",
			"filter": "testfilter1",
			"filter_environment": {"user": "testuser1"},
		},
		{
			"schema": "non_matching_schema",
			"filter": "testfilter2",
			"filter_environment": {"user": "testuser2"},
		},
		{
			"table": "non_matching_table",
			"filter": "testfilter3",
			"filter_environment": {"user": "testuser3"},
		},
		{
			"catalog": "testcatalog",
			"schema": "testschema",
			"table": "testtable",
			"filter": "testfilter4",
			"filter_environment": {"user": "testuser4"},
		},
		{
			"filter": "testfilter5",
			"filter_environment": {"user": "testuser5"},
		},
	]}
	request := {
		"operation": "GetRowFilters",
		"resource": {"table": {
			"catalogName": "testcatalog",
			"schemaName": "testschema",
			"tableName": "testtable",
		}},
	}

	response := trino_row_filters.row_filters with input as request
		with data.trino_policies.policies as policies

	response == {{
		"expression": "testfilter4",
		"identity": "testuser4",
	}}
}

test_row_filters_with_matching_rule_and_no_environment if {
	policies := {"tables": [
		{
			"catalog": "non_matching_catalog",
			"filter": "testfilter1",
		},
		{
			"schema": "non_matching_schema",
			"filter": "testfilter2",
		},
		{
			"table": "non_matching_table",
			"filter": "testfilter3",
		},
		{
			"catalog": "testcatalog",
			"schema": "testschema",
			"table": "testtable",
			"filter": "testfilter4",
		},
		{"filter": "testfilter5"},
	]}
	request := {
		"operation": "GetRowFilters",
		"resource": {"table": {
			"catalogName": "testcatalog",
			"schemaName": "testschema",
			"tableName": "testtable",
		}},
	}

	response := trino_row_filters.row_filters with input as request
		with data.trino_policies.policies as policies

	response == {{"expression": "testfilter4"}}
}

test_row_filters_with_matching_rule_and_no_filter if {
	policies := {"tables": [
		# This is the first matching rule even if no filter is defined.
		{
			"catalog": "testcatalog",
			"schema": "testschema",
			"table": "testtable",
		},
		{
			"catalog": "testcatalog",
			"schema": "testschema",
			"table": "testtable",
			"filter": "testfilter",
		},
	]}
	request := {
		"operation": "GetRowFilters",
		"resource": {"table": {
			"catalogName": "testcatalog",
			"schemaName": "testschema",
			"tableName": "testtable",
		}},
	}

	response := trino_row_filters.row_filters with input as request
		with data.trino_policies.policies as policies

	response == set()
}

test_row_filters_with_no_matching_rule if {
	policies := {"tables": [
		{
			"catalog": "non_matching_catalog",
			"filter": "testfilter1",
		},
		{
			"schema": "non_matching_schema",
			"filter": "testfilter2",
		},
		{
			"table": "non_matching_table",
			"filter": "testfilter3",
		},
		{"filter_environment": {"user": "testuser"}},
	]}
	request := {
		"operation": "GetRowFilters",
		"resource": {"table": {
			"catalogName": "testcatalog",
			"schemaName": "testschema",
			"tableName": "testtable",
		}},
	}

	response := trino_row_filters.row_filters with input as request
		with data.trino_policies.policies as policies

	response == set()
}

test_row_filters_with_no_rules if {
	policies := {}
	request := {
		"operation": "GetRowFilters",
		"resource": {"table": {
			"catalogName": "testcatalog",
			"schemaName": "testschema",
			"tableName": "testtable",
		}},
	}

	response := trino_row_filters.row_filters with input as request
		with data.trino_policies.policies as policies

	response == set()
}
