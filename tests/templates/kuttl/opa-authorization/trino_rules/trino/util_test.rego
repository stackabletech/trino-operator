package trino_test

import data.trino

test_match_entire if {
	trino.match_entire(`.*`, "a")
	trino.match_entire(`a`, "a")
	trino.match_entire(`^a`, "a")
	trino.match_entire(`a$`, "a")
	trino.match_entire(`^a$`, "a")
	not trino.match_entire(`a`, "abc")
	not trino.match_entire(`b`, "abc")
	not trino.match_entire(`c`, "abc")
}
