package sanitize

import (
	"regexp"
	"strings"
	"unicode"
)

const maxSanitizedLen = 256

// injectionPattern matches common NoSQL/SQL injection prefixes.
var injectionPattern = regexp.MustCompile(`^[\s]*[${}\\]"`)

// Metadata removes control characters, limits length, and rejects obvious injection patterns.
// Returns empty string if the value is considered unsafe.
func Metadata(value string) string {
	if value == "" {
		return ""
	}
	// Reject injection patterns
	if injectionPattern.MatchString(value) {
		return ""
	}
	// Remove control characters (0x00-0x1F, 0x7F)
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r >= 0x20 && r != 0x7F && r != unicode.ReplacementChar {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) > maxSanitizedLen {
		s = s[:maxSanitizedLen]
	}
	return strings.TrimSpace(s)
}
