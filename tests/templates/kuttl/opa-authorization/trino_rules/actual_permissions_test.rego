package actual_permissions_test

import data.trino
import rego.v1

test_match_entire if {
	trino.match_entire(`a`, "a")
	trino.match_entire(`^a`, "a")
	trino.match_entire(`a$`, "a")
	trino.match_entire(`^a$`, "a")
	not trino.match_entire(`a`, "abc")
	not trino.match_entire(`b`, "abc")
	not trino.match_entire(`c`, "abc")
}

test_impersonation_access_allow_specified_user if {
	trino.impersonation_access("testuser") with data.trino_policies.policies as {"impersonation": [{
		"original_user": "admin",
		"new_user": "testuser",
		"allow": true,
	}]}
		with input as {"context": {"identity": {
			"user": "admin",
			"groups": [],
		}}}
}

test_impersonation_access_allow_self if {
	trino.impersonation_access("admin") with data.trino_policies.policies as {"impersonation": [{
		"original_user": "admin",
		"new_user": "admin",
		"allow": false,
	}]}
		with input as {"context": {"identity": {
			"user": "admin",
			"groups": [],
		}}}
}

test_impersonation_access_allow_matching_user if {
	trino.impersonation_access("user_ihgfedcba") with data.trino_policies.policies as {"impersonation": [{
		"original_user": "user_(a)(b)(c)(d)(e)(f)(g)(h)(i)",
		"new_user": "user_$9$8$7$6$5$4$3$2$1",
		"allow": true,
	}]}
		with input as {"context": {"identity": {
			"user": "user_abcdefghi",
			"groups": [],
		}}}
}
