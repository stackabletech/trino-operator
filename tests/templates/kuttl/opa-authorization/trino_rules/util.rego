# METADATA
# description: Utility package which extends the built-in functions
package util

import rego.v1

# METADATA
# description: |
#   Matches the entire string against a regular expression.
#
#   pattern (string)  regular expression
#   value (string)    value to match against pattern
#
#   Returns:
#     result (boolean)
match_entire(pattern, value) if {
	# Add the anchors ^ and $
	pattern_with_anchors := concat("", ["^", pattern, "$"])

	regex.match(pattern_with_anchors, value)
}
