// Package pyjson reproduces, byte for byte, the parts of Python's json module
// that nday's stored data depends on.
//
// Why it exists: the Python implementation stores
// raw_record.content_hash = sha256(canonical_json(payload)) where
//
//	canonical_json(obj) = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
//
// and payload is whatever json.loads produced from the upstream body. To take
// over a database populated by Python without re-storing every raw record, the
// Go collectors must produce the SAME text for the same upstream bytes. That is
// not what encoding/json does (it escapes <, >, &, U+2028, normalises numbers
// to float64, has no NaN/Infinity, ...), hence this package.
//
// Value model (what Decode returns and Encode accepts):
//
//	nil                JSON null            (Python None)
//	bool               true / false         (Python bool)
//	string             JSON string          (Python str; must be valid UTF-8)
//	Int                integer literal      (Python int: arbitrary precision, kept as canonical decimal text)
//	float64            literal with . / e   (Python float, including NaN/±Inf)
//	[]any              array                (Python list)
//	*Object            object, ordered      (Python dict: insertion order, duplicate key = last value, first position)
//	map[string]any     object (encode only; convenient for building event detail)
//	int, int64         encode only, rendered like Int
//
// Python rules reproduced (CPython 3.12/3.13 json, verified with tests in
// this package and by recomputing every stored hash, see tools/hashparity):
//
//   - Decode: an integer literal (no '.', 'e', 'E') becomes Int ("-0" -> 0),
//     anything else becomes float64 (overflow -> ±Inf, as float() does);
//     NaN, Infinity, -Infinity are accepted; control characters inside strings
//     are rejected (strict=True); a UTF-8 BOM is skipped (json.loads(bytes)
//     decodes with utf-8-sig); only ' ', \t, \n, \r count as whitespace;
//     integer literals longer than 4300 digits are rejected (int max str digits).
//     Lone UTF-16 surrogate escapes are rejected: Python would accept them in
//     loads but then fail when hashing (UnicodeEncodeError) or storing, so the
//     run fails in both implementations, only at a different step.
//   - Encode: floats use repr() (shortest round-trip digits, exponent form when
//     exponent < -4 or >= 16, e.g. 1e-05, 1e+16, 1.2345678901234568e+17,
//     otherwise ".0" appended to integral values: 100.0, -0.0), NaN/Infinity
//     spelled as Python does; strings escape only " \ \b \f \n \r \t and other
//     C0 controls (as \u00XX, lowercase hex) when EnsureASCII is false; with
//     EnsureASCII every rune outside 0x20..0x7E becomes \uXXXX (surrogate pairs
//     above U+FFFF); keys are sorted by code point when SortKeys is set.
package pyjson
