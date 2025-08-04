package util_test

import data.util

test_match_entire if {
	util.match_entire(`.*`, "a")
	util.match_entire(`a`, "a")
	util.match_entire(`^a`, "a")
	util.match_entire(`a$`, "a")
	util.match_entire(`^a$`, "a")
	not util.match_entire(`a`, "abc")
	not util.match_entire(`b`, "abc")
	not util.match_entire(`c`, "abc")
}
