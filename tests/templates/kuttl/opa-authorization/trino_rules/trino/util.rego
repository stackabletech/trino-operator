package trino

# METADATA
# description: |
#   Matches the entire string against a regular expression.
#
#   pattern (string)  regular expression
#   value (string)    value to match against pattern
#
#   Returns:
#     result (boolean)
# scope: document
match_entire(`.*`, value)

match_entire(pattern, value) if {
	pattern != `.*`

	# Add the anchors ^ and $
	pattern_with_anchors := concat("", ["^", pattern, "$"])

	regex.match(pattern_with_anchors, value)
}
