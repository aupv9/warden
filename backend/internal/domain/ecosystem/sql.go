package ecosystem

// SQL forms of MatchName and MatchVersion, for comparing values that are
// stored as reported (issue.package_name, component.version) with normalized
// ones (component.match_name, malicious_package.versions). eco and the value
// are SQL expressions (columns or placeholders) chosen by the caller, never
// user input. Keep these in step with the Go functions; the store's
// integration tests compare the two.
//
// One known difference: Postgres lower() follows the database's ctype for
// non-ASCII letters, Go's strings.ToLower follows Unicode. Registry names and
// PyPI versions are ASCII in practice, and a mismatch only affects a count or
// a flag in a listing, never which issues exist.

// MatchNameSQL is MatchName(eco, name) as a SQL expression.
func MatchNameSQL(eco, name string) string {
	n := "lower(btrim(" + name + "))"
	return "(CASE " + eco + " WHEN '" + PyPI + "' THEN regexp_replace(" + n + ", '[-_.]+', '-', 'g')" +
		" WHEN '" + CratesIO + "' THEN replace(" + n + ", '_', '-') ELSE " + n + " END)"
}

// MatchVersionSQL is MatchVersion(eco, version) as a SQL expression.
func MatchVersionSQL(eco, version string) string {
	v := "btrim(" + version + ")"
	return "(CASE " + eco + " WHEN '" + Go + "' THEN (CASE WHEN left(" + v + ", 1) = 'v' THEN substr(" + v + ", 2) ELSE " + v + " END)" +
		" WHEN '" + PyPI + "' THEN lower(" + v + ") ELSE " + v + " END)"
}
