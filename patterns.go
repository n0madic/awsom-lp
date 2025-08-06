package awsomlp

import "regexp"

// Default header regex patterns for common log formats
const (
	// Universal pattern - matches timestamp/datetime prefix and captures content
	DefaultHeaderRegex = `^(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?[,:]\s*)?(.+)$`
	HDFSHeaderRegex    = `(\d{6} \d{6}) (\d+) (\w+) ([^:]+): (.+)`                                                   // HDFS format from paper
	SyslogHeaderRegex  = `^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+([^:]+):\s*(.+)$`                         // Syslog format
	JavaAppHeaderRegex = `^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(\w+)\s+\[([^\]]+)\]\s+([^-]+)-\s*(.+)$` // Java app format
)

// numericalPatterns are pre-compiled regular expressions for numerical variables
var numericalPatterns = []*regexp.Regexp{
	// Basic integers
	regexp.MustCompile(`\s\d+\s`),
	regexp.MustCompile(`\(\d+\)`),
	regexp.MustCompile(`\[\d+\]`),
	regexp.MustCompile(`\s\d+$`), // Numbers at end of line
	regexp.MustCompile(`^\d+\s`), // Numbers at beginning of line

	// Signed integers and floats (e.g., -123, 123.45, -456.78)
	regexp.MustCompile(`\s-?\d+(\.\d+)?\s`),
	regexp.MustCompile(`\(-?\d+(\.\d+)?\)`),
	regexp.MustCompile(`\[-?\d+(\.\d+)?\]`),
	regexp.MustCompile(`\s-?\d+(\.\d+)?$`), // At end of line
	regexp.MustCompile(`^-?\d+(\.\d+)?\s`), // At beginning of line

	// Hexadecimal values (e.g., 0x1a2b, 0X1A2B)
	regexp.MustCompile(`\s0[xX][0-9a-fA-F]+\s`),
	regexp.MustCompile(`\(0[xX][0-9a-fA-F]+\)`),
	regexp.MustCompile(`\[0[xX][0-9a-fA-F]+\]`),
	regexp.MustCompile(`\s0[xX][0-9a-fA-F]+$`), // At end of line
	regexp.MustCompile(`^0[xX][0-9a-fA-F]+\s`), // At beginning of line

	// Scientific notation (e.g., 1.23e-4, 5E+10)
	regexp.MustCompile(`\s-?\d+(\.\d+)?[eE][+-]?\d+\s`),
	regexp.MustCompile(`\(-?\d+(\.\d+)?[eE][+-]?\d+\)`),
	regexp.MustCompile(`\[-?\d+(\.\d+)?[eE][+-]?\d+\]`),
	regexp.MustCompile(`\s-?\d+(\.\d+)?[eE][+-]?\d+$`), // At end of line
	regexp.MustCompile(`^-?\d+(\.\d+)?[eE][+-]?\d+\s`), // At beginning of line

	// Numbers with units (e.g., 100KB, 2.5MB, 10ms)
	regexp.MustCompile(`\s-?\d+(\.\d+)?[a-zA-Z]+\s`),
	regexp.MustCompile(`\(-?\d+(\.\d+)?[a-zA-Z]+\)`),
	regexp.MustCompile(`\[-?\d+(\.\d+)?[a-zA-Z]+\]`),
	regexp.MustCompile(`\s-?\d+(\.\d+)?[a-zA-Z]+$`), // At end of line
	regexp.MustCompile(`^-?\d+(\.\d+)?[a-zA-Z]+\s`), // At beginning of line

	// Identifiers with format prefix_number (e.g., blk_123, id_456, task_789)
	regexp.MustCompile(`\s[a-zA-Z]+_-?\d+\s`),
	regexp.MustCompile(`\([a-zA-Z]+_-?\d+\)`),
	regexp.MustCompile(`\[[a-zA-Z]+_-?\d+\]`),
	regexp.MustCompile(`\s[a-zA-Z]+_-?\d+$`), // At end of line
	regexp.MustCompile(`^[a-zA-Z]+_-?\d+\s`), // At beginning of line
}

// trivialVarPatterns are pre-compiled regular expressions for trivial variables
var trivialVarPatterns = []*regexp.Regexp{
	// Directory paths (Unix and Windows) - keep full paths
	regexp.MustCompile(`(/[a-zA-Z0-9._/-]+){3,}`),       // Only long paths (3+ segments)
	regexp.MustCompile(`([a-zA-Z]:\\[\w\s\\./-]+){2,}`), // Only long Windows paths

	// IPv4 addresses with optional port and optional leading slash (for HDFS logs)
	regexp.MustCompile(`/?(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?`),

	// IPv6 addresses
	regexp.MustCompile(`\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),

	// Hex values (0x...)
	regexp.MustCompile(`0x[0-9a-fA-F]{4,}`), // Only longer hex values

	// MAC addresses
	regexp.MustCompile(`([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}`),

	// UUIDs
	regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),

	// Hashes (MD5, SHA1, SHA256, etc.)
	regexp.MustCompile(`\b[a-fA-F0-9]{32,64}\b`),

	// === Comprehensive datetime format recognition ===

	// ISO 8601 timestamps with T separator and optional timezone
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)?`), // 2024-01-15T10:30:15.123Z

	// Standard datetime with space separator
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(\.\d+)?`), // 2024-01-15 10:30:15.123

	// Date with slashes DD/MM/YYYY or MM/DD/YYYY with time
	regexp.MustCompile(`\d{1,2}/\d{1,2}/\d{4}\s+\d{2}:\d{2}:\d{2}(\.\d+)?`), // 15/01/2024 10:30:15 or 01/15/2024 10:30:15

	// Date with month name - various formats
	regexp.MustCompile(`\d{1,2}[- ](Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[- ]\d{4}\s+\d{2}:\d{2}:\d{2}(\.\d+)?`), // 31-Jul-2025 10:38:24
	regexp.MustCompile(`(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}(\.\d+)?`),   // Jul 31 2025 10:38:30.789
	regexp.MustCompile(`\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}(\.\d+)?`),   // 31 Jul 2025 10:38:30.789

	// Syslog-style timestamps (month day time, no year)
	regexp.MustCompile(`(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}`), // Jan 15 10:30:15

	// Reverse date format YYYY/MM/DD
	regexp.MustCompile(`\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(\.\d+)?`), // 2024/01/15 10:30:15

	// European format DD.MM.YYYY
	regexp.MustCompile(`\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}:\d{2}(\.\d+)?`), // 15.01.2024 10:30:15

	// Date only formats (without time)
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}`),     // 2024-01-15
	regexp.MustCompile(`\d{1,2}/\d{1,2}/\d{4}`), // 15/01/2024 or 01/15/2024
	regexp.MustCompile(`\d{2}\.\d{2}\.\d{4}`),   // 15.01.2024

	// Compact formats (with word boundaries to avoid matching parts of IDs)
	regexp.MustCompile(`\b\d{8}T\d{6}\b`), // 20240115T103015
	regexp.MustCompile(`\b\d{14}\b`),      // 20240115103015

	// Unix timestamps (10 or 13 digits, starting with 1 for year 2001+ timestamps)
	regexp.MustCompile(`\b1[0-9]{9}\b`),  // 10-digit Unix timestamp (seconds since 1970)
	regexp.MustCompile(`\b1[0-9]{12}\b`), // 13-digit Unix timestamp (milliseconds since 1970)

	// Months standalone (for partial date matching)
	regexp.MustCompile(`\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December)\b`),

	// Days of week
	regexp.MustCompile(`\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\b`),

	// Time only patterns (without date)
	regexp.MustCompile(`\b\d{1,2}:\d{2}:\d{2}(\.\d{1,6})?\b`), // 10:30:15.123

	// Full URLs
	regexp.MustCompile(`https?://[^\s]+`),
	regexp.MustCompile(`ftp://[^\s]+`),

	// Email addresses
	regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),

	// Words in parentheses (like controller names, user roles, etc.)
	regexp.MustCompile(`\([a-zA-Z][a-zA-Z0-9_-]*\)`),

	// Very long alphanumeric strings (likely IDs/tokens)
	regexp.MustCompile(`\b[a-zA-Z0-9]{32,}\b`), // Only very long strings
}
