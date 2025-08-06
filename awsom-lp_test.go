package awsomlp

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Test data
var hdfsTestLogs = []string{
	"081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating",
	"081109 203807 149 INFO dfs.DataNode$PacketResponder: PacketResponder 0 for block blk_-6952295868487656571 terminating",
	"081109 204005 150 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: blockMap updated: 10.251.73.220:50010 is added to blk_7128370237687728475 size 67108864",
	"081110 205017 151 INFO dfs.DataNode$PacketResponder: PacketResponder 2 for block blk_8229193803249955061 terminating",
	"081111 031815 157 INFO dfs.DataNode$DataXceiver: Received block blk_-380655686551609279 of size 67108864 from /10.251.91.84",
}

// Test logs for paper compliance validation (PacketResponder example from paper)
var paperComplianceTestLogs = []string{
	"PacketResponder 1 for block blk_12345 terminating",
	"PacketResponder 0 for block blk_67890 terminating",
	"PacketResponder 2 for block blk_11111 terminating",
}

func TestNewAWSOMLP(t *testing.T) {
	parser := NewAWSOMLP()

	if parser == nil {
		t.Fatal("NewAWSOMLP() returned nil")
	}

	// Test default configuration
	expected := DefaultConfig()
	if parser.config.MinSimilarity != expected.MinSimilarity {
		t.Errorf("Expected MinSimilarity %f, got %f", expected.MinSimilarity, parser.config.MinSimilarity)
	}

	if parser.config.SortingStrategy != expected.SortingStrategy {
		t.Errorf("Expected SortingStrategy %v, got %v", expected.SortingStrategy, parser.config.SortingStrategy)
	}

	// Test initialization
	if parser.patterns == nil {
		t.Error("patterns slice not initialized")
	}

	// Test that we can get templates (this validates internal structure)
	templates := parser.GetTemplates()
	if templates == nil {
		t.Error("GetTemplates() returned nil")
	}
	// Empty templates is expected for new parser before parsing
	if len(templates) != 0 {
		t.Errorf("Expected empty templates for new parser, got %d", len(templates))
	}

	if len(trivialVarPatterns) == 0 {
		t.Error("trivialVarPatterns not initialized")
	}

	if len(parser.customRegexes) != 0 {
		t.Error("customRegexes should be empty for default configuration")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.MinSimilarity != 1.0 {
		t.Errorf("Expected MinSimilarity 1.0, got %f", config.MinSimilarity)
	}

	if config.SortingStrategy != SortNone {
		t.Errorf("Expected SortingStrategy SortNone, got %v", config.SortingStrategy)
	}

	if config.HeaderRegex != DefaultHeaderRegex {
		t.Errorf("Expected HeaderRegex %s, got %s", DefaultHeaderRegex, config.HeaderRegex)
	}

	if config.CustomRegexes == nil {
		t.Error("CustomRegexes should be initialized (empty slice)")
	}
}

func TestWithConfig(t *testing.T) {
	parser := NewAWSOMLP()

	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid full config",
			config: Config{
				MinSimilarity:   0.8,
				SortingStrategy: SortByLength,
				HeaderRegex:     HDFSHeaderRegex,
				CustomRegexes:   []string{`test_\d+`},
			},
			expectError: false,
		},
		{
			name: "Partial config with defaults",
			config: Config{
				SortingStrategy: SortLexical,
			},
			expectError: false,
		},
		{
			name: "Invalid MinSimilarity - too high",
			config: Config{
				MinSimilarity: 1.5,
			},
			expectError: true,
			errorMsg:    "MinSimilarity must be between 0 and 1",
		},
		{
			name: "Invalid MinSimilarity - negative",
			config: Config{
				MinSimilarity: -0.1,
			},
			expectError: true,
			errorMsg:    "MinSimilarity must be between 0 and 1",
		},
		{
			name: "Invalid HeaderRegex",
			config: Config{
				HeaderRegex: "[invalid regex",
			},
			expectError: true,
			errorMsg:    "invalid HeaderRegex",
		},
		{
			name: "Invalid CustomRegex",
			config: Config{
				CustomRegexes: []string{"[invalid regex"},
			},
			expectError: true,
			errorMsg:    "invalid custom regex pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parser.WithConfig(tt.config)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestWithConfigDefaults(t *testing.T) {
	parser := NewAWSOMLP()

	// Test that zero values get replaced with defaults
	config := Config{
		SortingStrategy: SortByLength, // Only set this
	}

	err := parser.WithConfig(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check that defaults were applied
	if parser.config.MinSimilarity != 1.0 {
		t.Errorf("Expected default MinSimilarity 1.0, got %f", parser.config.MinSimilarity)
	}

	if parser.config.HeaderRegex != DefaultHeaderRegex {
		t.Errorf("Expected default HeaderRegex, got %s", parser.config.HeaderRegex)
	}

	if parser.config.SortingStrategy != SortByLength {
		t.Errorf("Expected SortByLength, got %v", parser.config.SortingStrategy)
	}
}

func TestPreprocess(t *testing.T) {
	parser := NewAWSOMLP()

	// Configure with HDFS header
	config := Config{
		HeaderRegex: HDFSHeaderRegex,
	}
	err := parser.WithConfig(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	testLog := "081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating"
	event := parser.Preprocess(testLog)

	if event.Raw != testLog {
		t.Errorf("Expected Raw to be original log, got %s", event.Raw)
	}

	// Should have removed timestamp, level, etc. Block IDs remain unchanged during preprocessing
	// (they will be replaced later during Numerical Variable Replacement stage)
	expectedContent := "PacketResponder 1 for block blk_38865049064139660 terminating"
	if event.Content != expectedContent {
		t.Errorf("Expected Content '%s', got '%s'", expectedContent, event.Content)
	}

	// Should have tokenized - block ID remains unchanged at this stage
	expectedTokens := []string{"PacketResponder", "1", "for", "block", "blk_38865049064139660", "terminating"}
	if !reflect.DeepEqual(event.Tokens, expectedTokens) {
		t.Errorf("Expected Tokens %v, got %v", expectedTokens, event.Tokens)
	}
}

func TestPatternRecognition(t *testing.T) {
	parser := NewAWSOMLP()

	config := Config{
		HeaderRegex: HDFSHeaderRegex,
	}
	err := parser.WithConfig(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Preprocess logs
	events := make([]*LogEvent, 0)
	for _, logLine := range hdfsTestLogs {
		event := parser.Preprocess(logLine)
		events = append(events, event)
	}

	// Run pattern recognition
	parser.patternRecognition(events)

	// Should have created patterns
	if len(parser.patterns) == 0 {
		t.Error("Expected patterns to be created")
	}

	// Check that similar events are grouped together
	packetResponderCount := 0
	for _, pattern := range parser.patterns {
		for _, event := range pattern.Events {
			if strings.Contains(event.Content, "PacketResponder") {
				packetResponderCount++
			}
		}
	}

	// Should have 3 PacketResponder events
	if packetResponderCount != 3 {
		t.Errorf("Expected 3 PacketResponder events, got %d", packetResponderCount)
	}
}

func TestParse(t *testing.T) {
	parser := NewAWSOMLP()

	config := Config{
		HeaderRegex: HDFSHeaderRegex,
	}
	err := parser.WithConfig(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	results := parser.Parse(hdfsTestLogs)

	// Should have results for all input logs
	if len(results) != len(hdfsTestLogs) {
		t.Errorf("Expected %d results, got %d", len(hdfsTestLogs), len(results))
	}

	// Check that each log has a template
	for _, logLine := range hdfsTestLogs {
		template, exists := results[logLine]
		if !exists {
			t.Errorf("No template found for log: %s", logLine)
			continue
		}

		if template == "" {
			t.Errorf("Empty template for log: %s", logLine)
		}

		// Template should contain <*> placeholders
		if !strings.Contains(template, "<*>") {
			t.Errorf("Template should contain <*> placeholders, got: %s", template)
		}
	}
}

func TestGetTemplates(t *testing.T) {
	parser := NewAWSOMLP()

	config := Config{
		HeaderRegex: HDFSHeaderRegex,
	}
	err := parser.WithConfig(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Parse some logs
	parser.Parse(hdfsTestLogs)

	templates := parser.GetTemplates()

	if len(templates) == 0 {
		t.Error("Expected some templates to be generated")
	}

	// Templates should be sorted
	for i := 1; i < len(templates); i++ {
		if templates[i-1] > templates[i] {
			t.Error("Templates should be sorted alphabetically")
			break
		}
	}

	// Should not have duplicates (since we use a map internally)
	templateMap := make(map[string]bool)
	for _, template := range templates {
		if templateMap[template] {
			t.Errorf("Duplicate template found: %s", template)
		}
		templateMap[template] = true
	}
}

func TestGetPatterns(t *testing.T) {
	parser := NewAWSOMLP()

	config := Config{
		HeaderRegex: HDFSHeaderRegex,
	}
	err := parser.WithConfig(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Parse some logs
	parser.Parse(hdfsTestLogs)

	patterns := parser.GetPatterns()

	if len(patterns) == 0 {
		t.Error("Expected some patterns to be generated")
	}

	// Check pattern structure
	for i, pattern := range patterns {
		if pattern.ID != i {
			t.Errorf("Expected pattern ID %d, got %d", i, pattern.ID)
		}

		if len(pattern.Events) == 0 {
			t.Errorf("Pattern %d should have events", i)
		}

		if pattern.Template == "" {
			t.Errorf("Pattern %d should have a template", i)
		}

		if pattern.Frequency == nil {
			t.Errorf("Pattern %d should have frequency map", i)
		}
	}
}

func TestSortingStrategies(t *testing.T) {
	testLogs := []string{
		"INFO: Short log",
		"INFO: This is a much longer log with more tokens",
		"INFO: Medium length log message",
	}

	strategies := []struct {
		name     string
		strategy SortingStrategy
	}{
		{"SortNone", SortNone},
		{"SortByLength", SortByLength},
		{"SortLexical", SortLexical},
		{"SortByDynTokens", SortByDynTokens},
	}

	for _, s := range strategies {
		t.Run(s.name, func(t *testing.T) {
			parser := NewAWSOMLP()

			config := Config{
				SortingStrategy: s.strategy,
			}
			err := parser.WithConfig(config)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			results := parser.Parse(testLogs)

			// Should have results for all logs
			if len(results) != len(testLogs) {
				t.Errorf("Expected %d results, got %d", len(testLogs), len(results))
			}

			// Results should be deterministic for the same input
			results2 := parser.Parse(testLogs)
			if !reflect.DeepEqual(results, results2) {
				t.Error("Results should be deterministic")
			}
		})
	}
}

func TestEmptyInput(t *testing.T) {
	parser := NewAWSOMLP()

	// Test with empty slice
	results := parser.Parse([]string{})
	if len(results) != 0 {
		t.Error("Expected empty results for empty input")
	}

	// Test with nil slice
	results = parser.Parse(nil)
	if len(results) != 0 {
		t.Error("Expected empty results for nil input")
	}

	// Test with empty strings
	results = parser.Parse([]string{"", "  ", "\t\n"})
	if len(results) != 0 {
		t.Error("Expected empty results for whitespace-only input")
	}
}

func TestCustomRegexes(t *testing.T) {
	parser := NewAWSOMLP()

	config := Config{
		CustomRegexes: []string{
			`test_\d+`,          // Custom pattern for test IDs
			`session_[a-f0-9]+`, // Custom pattern for session IDs
		},
	}
	err := parser.WithConfig(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	testLogs := []string{
		"Processing test_123 with session_abc123def",
		"Processing test_456 with session_789fedcba",
	}

	results := parser.Parse(testLogs)

	// Check that custom patterns were replaced
	for _, template := range results {
		// Should have replaced test_XXX and session_XXX with <*>
		if strings.Contains(template, "test_") || strings.Contains(template, "session_") {
			t.Errorf("Custom regex patterns not replaced in template: %s", template)
		}
	}
}

// TestOriginalPaperExample tests with exact example from the original AWSOM-LP paper
// to verify our algorithm implementation matches the expected output from the paper.
// IMPORTANT: This test data and expected results MUST NOT be modified - if this test
// fails, it means our implementation differs from the original algorithm and needs to be fixed.
// The test uses examples from Figure 2 of the paper and expects the exact templates shown there.
func TestOriginalPaperExample(t *testing.T) {
	parser := NewAWSOMLP()

	// Use paper-compliant configuration for exact match with the original algorithm
	// DO NOT add custom regexes here - the algorithm should handle HDFS blocks automatically
	config := Config{
		HeaderRegex:         HDFSHeaderRegex,
		MinGroupSize:        1,   // Paper allows single-event groups
		MaxPlaceholderRatio: 1.0, // No placeholder restrictions in paper
		MinTemplateTokens:   0,   // No minimum token restrictions in paper
	}
	err := parser.WithConfig(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Exact log examples from the original paper (Figure 2)
	originalLogs := []string{
		"081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating",
		"081109 203807 149 INFO dfs.DataNode$PacketResponder: PacketResponder 0 for block blk_-6952295868487656571 terminating",
		"081109 204005 150 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: blockMap updated: 10.251.73.220:50010 is added to blk_7128370237687728475 size 67108864",
		"081109 204015 308 INFO dfs.DataNode$PacketResponder: PacketResponder 2 for block blk_8229193803249955061 terminating",
		"081109 208106 329 INFO dfs.DataNode$PacketResponder: PacketResponder 2 for block blk_-6670958622368987959 terminating",
		"081109 204132 26 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: blockMap updated: 10.251.203.80:50010 is added to blk_950920557425079149 size 67105864",
		"081109 204328 34 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: blockMap updated: 10.251.203.80:50010 is added to blk_7688946331004732825 size 67105864",
		"081109 205135 611 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: blockMap updated: 10.250.11.85:50010 is added to blk_2377150260125000006 size 67108064",
		"081109 204525 512 INFO dfs.DataNode$PacketResponder: PacketResponder 2 for block blk_572492839287299681 terminating",
		"081109 201655 556 INFO dfs.DataNode$PacketResponder: Received block blk_3587505140051952248 of size 67108864 from /10.251.42.84",
		"081109 204722 567 INFO dfs.DataNode$PacketResponder: Received block blk_5407003568334525940 of size 67108864 from /10.251.214.112",
		"081109 204815 653 INFO dfs.DataNode$PacketResponder: Received block blk_9212264480425680329 of size 67108864 from /10.251.214.111",
	}

	results := parser.Parse(originalLogs)

	// Verify that we have results for all logs
	if len(results) != len(originalLogs) {
		t.Errorf("Expected %d results, got %d", len(originalLogs), len(results))
	}

	// Get all templates
	templates := parser.GetTemplates()

	// According to the paper, there should be 3 templates
	expectedTemplateCount := 3
	if len(templates) != expectedTemplateCount {
		t.Errorf("Expected %d templates, got %d. Templates: %v", expectedTemplateCount, len(templates), templates)
	}

	// Expected templates from the paper (after all steps including numerical replacement)
	expectedTemplates := []string{
		"BLOCK* NameSystem.addStoredBlock: blockMap updated: <*> is added to <*> size <*>",
		"PacketResponder <*> for block <*> terminating",
		"Received block <*> of size <*> from <*>",
	}

	// Sort both slices to compare them
	sort.Strings(expectedTemplates)
	actualTemplates := make([]string, len(templates))
	copy(actualTemplates, templates)
	sort.Strings(actualTemplates)

	// Check if we have the expected templates
	for i, expected := range expectedTemplates {
		if i >= len(actualTemplates) {
			t.Errorf("Missing expected template: %s", expected)
			continue
		}

		if actualTemplates[i] != expected {
			t.Errorf("Template mismatch at index %d:\nExpected: %s\nActual:   %s", i, expected, actualTemplates[i])
		}
	}

	// Verify specific log mappings from the paper
	testCases := []struct {
		log      string
		template string
	}{
		{
			"081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating",
			"PacketResponder <*> for block <*> terminating",
		},
		{
			"081109 204005 150 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: blockMap updated: 10.251.73.220:50010 is added to blk_7128370237687728475 size 67108864",
			"BLOCK* NameSystem.addStoredBlock: blockMap updated: <*> is added to <*> size <*>",
		},
		{
			"081109 201655 556 INFO dfs.DataNode$PacketResponder: Received block blk_3587505140051952248 of size 67108864 from /10.251.42.84",
			"Received block <*> of size <*> from <*>",
		},
	}

	for _, tc := range testCases {
		actualTemplate, exists := results[tc.log]
		if !exists {
			t.Errorf("No template found for log: %s", tc.log)
			continue
		}

		if actualTemplate != tc.template {
			t.Errorf("Template mismatch for log:\n%s\nExpected: %s\nActual:   %s", tc.log, tc.template, actualTemplate)
		}
	}

	t.Logf("Successfully parsed %d logs into %d templates matching the original paper", len(originalLogs), len(templates))
}

// Benchmark tests
func BenchmarkPreprocess(b *testing.B) {
	parser := NewAWSOMLP()
	config := Config{HeaderRegex: HDFSHeaderRegex}
	parser.WithConfig(config)

	testLog := "081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.Preprocess(testLog)
	}
}

func BenchmarkParseWithSorting(b *testing.B) {
	strategies := []SortingStrategy{SortNone, SortByLength, SortLexical, SortByDynTokens}

	for _, strategy := range strategies {
		b.Run(strategy.String(), func(b *testing.B) {
			parser := NewAWSOMLP()
			config := Config{
				HeaderRegex:     HDFSHeaderRegex,
				SortingStrategy: strategy,
			}
			parser.WithConfig(config)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				parser.Parse(hdfsTestLogs)
			}
		})
	}
}

// String method for SortingStrategy for benchmark names
func (s SortingStrategy) String() string {
	switch s {
	case SortNone:
		return "SortNone"
	case SortByLength:
		return "SortByLength"
	case SortLexical:
		return "SortLexical"
	case SortByDynTokens:
		return "SortByDynTokens"
	default:
		return "Unknown"
	}
}

// TestEdgeCases tests edge cases that were problematic in earlier versions
func TestEdgeCases(t *testing.T) {
	testCases := []struct {
		name          string
		logs          []string
		expectedCount int // Number of unique templates expected
		description   string
	}{
		{
			name: "Variables in parentheses",
			logs: []string{
				"Invalid controller specified (publishers)",
				"Invalid controller specified (admin)",
				"Invalid controller specified (users)",
				"Invalid controller specified (guests)",
			},
			expectedCount: 1,
			description:   "Should replace variables in parentheses with <*>",
		},
		{
			name: "Single unique messages",
			logs: []string{
				"Single unique error message that should not be lost",
				"Another single unique warning",
				"Standalone info message",
			},
			expectedCount: 3,
			description:   "Each unique message should produce its own template",
		},
		{
			name: "Identical messages",
			logs: []string{
				"Server started successfully",
				"Server started successfully",
				"Server started successfully",
				"Server started successfully",
			},
			expectedCount: 1,
			description:   "Identical messages should produce one template",
		},
		{
			name: "Mixed paths and variables",
			logs: []string{
				"Access to script '/path/one.php' denied",
				"Access to script '/path/two.php' denied",
				"Access to script '/path/three.php' denied",
			},
			expectedCount: 1,
			description:   "Paths in quotes should be replaced with <*>",
		},
		{
			name: "Small group with variables",
			logs: []string{
				"Server 'http_server' running without auth",
				"Server 'tcp_server' running without auth",
			},
			expectedCount: 1,
			description:   "Small groups should still replace variables",
		},
		{
			name: "Timestamps in messages",
			logs: []string{
				"2024-01-15 10:30:45 Unique log with timestamp",
				"2024-01-16 11:45:30 Unique log with timestamp",
				"2024-01-17 09:15:22 Unique log with timestamp",
			},
			expectedCount: 1,
			description:   "Timestamps should be replaced with <*>",
		},
		{
			name: "Empty and whitespace logs",
			logs: []string{
				"",
				"   ",
				"\t",
				"Valid log message",
				"  \n  ",
				"Another valid message",
			},
			expectedCount: 2,
			description:   "Empty logs should be ignored, only valid ones processed",
		},
		{
			name: "Numbers in various contexts",
			logs: []string{
				"Error code 404 occurred",
				"Error code 500 occurred",
				"Error code 403 occurred",
			},
			expectedCount: 1,
			description:   "Numbers should be replaced with <*>",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewAWSOMLP()
			results := parser.Parse(tc.logs)

			// Count non-empty unique input logs
			uniqueLogs := make(map[string]bool)
			for _, log := range tc.logs {
				if strings.TrimSpace(log) != "" {
					uniqueLogs[log] = true
				}
			}

			// Verify we have results for all unique non-empty logs
			if len(results) != len(uniqueLogs) {
				t.Errorf("%s: Expected results for %d unique non-empty logs, got %d results",
					tc.name, len(uniqueLogs), len(results))
			}

			// Count unique templates
			uniqueTemplates := make(map[string]bool)
			for _, template := range results {
				uniqueTemplates[template] = true
			}

			if len(uniqueTemplates) != tc.expectedCount {
				t.Errorf("%s: Expected %d unique templates, got %d. Templates: %v\nDescription: %s",
					tc.name, tc.expectedCount, len(uniqueTemplates), uniqueTemplates, tc.description)
			}

			// Verify no empty templates
			for log, template := range results {
				if strings.TrimSpace(template) == "" {
					t.Errorf("%s: Got empty template for log: %s", tc.name, log)
				}
			}
		})
	}
}

// TestResultCountMatchesInput verifies that every non-empty input log gets a result
func TestResultCountMatchesInput(t *testing.T) {
	testLogs := []string{
		"Error occurred in module A",
		"Warning: low memory",
		"", // Empty - should be ignored
		"Info: system started",
		"   ", // Whitespace - should be ignored
		"Debug: processing request 12345",
		"Error occurred in module B",
		"\t\n", // Whitespace - should be ignored
		"Critical: disk full",
		"Info: system stopped",
	}

	parser := NewAWSOMLP()
	results := parser.Parse(testLogs)

	// Count non-empty logs
	expectedCount := 0
	for _, log := range testLogs {
		if strings.TrimSpace(log) != "" {
			expectedCount++
		}
	}

	if len(results) != expectedCount {
		t.Errorf("Result count mismatch: expected %d results for non-empty logs, got %d",
			expectedCount, len(results))
	}

	// Verify each non-empty log has a result
	for _, log := range testLogs {
		if strings.TrimSpace(log) != "" {
			if _, exists := results[log]; !exists {
				t.Errorf("Missing result for log: %s", log)
			}
		}
	}
}

// TestNoEmptyTemplates verifies that no empty templates are generated
func TestNoEmptyTemplates(t *testing.T) {
	// Test logs that previously produced empty templates
	testLogs := []string{
		"Invalid controller specified (publishers)",
		"Invalid controller specified (admin)",
		"Single unique message",
		"2024-01-15 10:30:45 Log with timestamp",
		"Error 404",
		"Error 500",
		"Path /var/log/app.log not found",
		"IP 192.168.1.1 connected",
	}

	parser := NewAWSOMLP()
	results := parser.Parse(testLogs)

	for log, template := range results {
		if strings.TrimSpace(template) == "" {
			t.Errorf("Empty template generated for log: %s", log)
		}

		// Check for degenerate templates (only placeholders)
		tokens := strings.Fields(template)
		allPlaceholders := true
		for _, token := range tokens {
			if token != "<*>" {
				allPlaceholders = false
				break
			}
		}

		if allPlaceholders && len(tokens) > 0 {
			t.Errorf("Degenerate template (only placeholders) for log: %s -> %s", log, template)
		}
	}
}

// TestVariableReplacementInParentheses specifically tests parentheses handling
func TestVariableReplacementInParentheses(t *testing.T) {
	logs := []string{
		"Invalid controller specified (publishers)",
		"Invalid controller specified (admin)",
		"Invalid controller specified (users)",
		"Invalid controller specified (managers)",
	}

	parser := NewAWSOMLP()
	results := parser.Parse(logs)

	// All should map to the same template
	expectedTemplate := "Invalid controller specified <*>"
	templates := make(map[string]int)

	for log, template := range results {
		templates[template]++
		if template != expectedTemplate {
			t.Errorf("Expected template '%s' for log '%s', got '%s'",
				expectedTemplate, log, template)
		}
	}

	// Should have only one unique template
	if len(templates) != 1 {
		t.Errorf("Expected 1 unique template, got %d: %v", len(templates), templates)
	}
}

// TestDuplicateLogHandling tests that duplicate logs are handled correctly
func TestDuplicateLogHandling(t *testing.T) {
	logs := []string{
		"Message A",
		"Message A", // Duplicate
		"Message B",
		"Message C",
		"Message B", // Duplicate
		"Message A", // Another duplicate
	}

	parser := NewAWSOMLP()
	results := parser.Parse(logs)

	// Results map should have unique logs as keys
	expectedUniqueCount := 3 // A, B, C
	if len(results) != expectedUniqueCount {
		t.Errorf("Expected %d unique results, got %d", expectedUniqueCount, len(results))
	}

	// Verify each unique message has a result
	if _, exists := results["Message A"]; !exists {
		t.Error("Missing result for 'Message A'")
	}
	if _, exists := results["Message B"]; !exists {
		t.Error("Missing result for 'Message B'")
	}
	if _, exists := results["Message C"]; !exists {
		t.Error("Missing result for 'Message C'")
	}
}

// TestSmallGroupHandling tests that small groups are handled correctly
func TestSmallGroupHandling(t *testing.T) {
	parser := NewAWSOMLP()

	// Configure with MinGroupSize = 3
	config := DefaultConfig()
	config.MinGroupSize = 3
	parser.WithConfig(config)

	// Test with groups smaller than MinGroupSize
	logs := []string{
		"Rare error message one",
		"Rare error message two",
		"Common message",
		"Common message",
		"Common message",
		"Common message",
	}

	results := parser.Parse(logs)

	// Count unique logs
	uniqueLogs := make(map[string]bool)
	for _, log := range logs {
		uniqueLogs[log] = true
	}

	// Verify all unique logs have results
	if len(results) != len(uniqueLogs) {
		t.Errorf("Expected %d results for unique logs, got %d", len(uniqueLogs), len(results))
	}

	// Small group (2 logs) should use preprocessed content
	// Large group (4 logs) should use frequency analysis
	for log, template := range results {
		if strings.TrimSpace(template) == "" {
			t.Errorf("Empty template for log: %s", log)
		}
	}

	// Verify we have the expected templates
	if _, exists := results["Rare error message one"]; !exists {
		t.Error("Missing result for 'Rare error message one'")
	}
	if _, exists := results["Rare error message two"]; !exists {
		t.Error("Missing result for 'Rare error message two'")
	}
	if _, exists := results["Common message"]; !exists {
		t.Error("Missing result for 'Common message'")
	}
}

// TestDatetimeFormatRecognition tests comprehensive datetime format recognition
func TestDatetimeFormatRecognition(t *testing.T) {
	testCases := []struct {
		name        string
		logs        []string
		description string
	}{
		{
			name: "ISO 8601 timestamps",
			logs: []string{
				"Error occurred at 2024-01-15T10:30:15.123Z in system",
				"Error occurred at 2024-01-16T11:45:30Z in system",
				"Error occurred at 2024-01-17T09:15:22.456789Z in system",
			},
			description: "ISO 8601 timestamps should be replaced with <*>",
		},
		{
			name: "Standard datetime formats",
			logs: []string{
				"2024-01-15 10:30:15.123 System started successfully",
				"2024-01-16 11:45:30 System started successfully",
				"2024-01-17 09:15:22 System started successfully",
			},
			description: "Standard datetime should be replaced with <*>",
		},
		{
			name: "Slash date formats",
			logs: []string{
				"15/01/2024 10:30:15 Process completed",
				"01/15/2024 11:45:30 Process completed",
				"16/02/2024 09:15:22.789 Process completed",
			},
			description: "Slash date formats should be replaced with <*>",
		},
		{
			name: "Month name formats",
			logs: []string{
				"31-Jul-2025 10:38:24 Server initialized",
				"15-Jan-2024 11:45:30 Server initialized",
				"31 Jul 2025 10:38:30.789 Server initialized",
			},
			description: "Month name formats should be replaced with <*>",
		},
		{
			name: "European date formats",
			logs: []string{
				"15.01.2024 10:30:15 Database query executed",
				"16.02.2024 11:45:30.123 Database query executed",
			},
			description: "European date formats should be replaced with <*>",
		},
		{
			name: "Unix timestamps",
			logs: []string{
				"Event logged at timestamp 1705312215 with result success",
				"Event logged at timestamp 1705312218 with result success",
				"Event logged at timestamp 1705312215123 with result success",
			},
			description: "Unix timestamps should be replaced with <*>",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewAWSOMLP()
			results := parser.Parse(tc.logs)

			// Count unique templates
			uniqueTemplates := make(map[string]bool)
			for _, template := range results {
				uniqueTemplates[template] = true
			}

			// Should produce 1 unique template (all dates replaced with <*>)
			expectedTemplates := 1
			if len(uniqueTemplates) != expectedTemplates {
				t.Errorf("%s: Expected %d unique templates, got %d. Templates: %v\nDescription: %s",
					tc.name, expectedTemplates, len(uniqueTemplates), uniqueTemplates, tc.description)
			}

			// Verify datetime patterns are replaced
			for log, template := range results {
				// Check that template contains <*> where datetime was
				if !strings.Contains(template, "<*>") {
					t.Errorf("%s: Template should contain <*> placeholder for datetime. Log: %s, Template: %s",
						tc.name, log, template)
				}

				// Verify specific datetime patterns are NOT in the template
				datePatterns := []string{
					"2024-", "2025-", "T10:", "T11:", "T09:", ".123", ".789", "Z",
					"15/01/", "01/15/", "16/02/",
					"31-Jul", "15-Jan", "Jan 15",
					"15.01.", "16.02.",
					"1705312",
				}
				for _, pattern := range datePatterns {
					if strings.Contains(template, pattern) {
						t.Errorf("%s: Template still contains datetime pattern '%s'. Log: %s, Template: %s",
							tc.name, pattern, log, template)
					}
				}
			}
		})
	}
}

// TestPaperCompliance validates that default configuration matches paper behavior
func TestPaperCompliance(t *testing.T) {
	parser := NewAWSOMLP()

	// Use default configuration which should be paper-compliant
	results := parser.Parse(paperComplianceTestLogs)

	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	// Find the template for PacketResponder logs
	var template string
	for _, tmpl := range results {
		if strings.Contains(tmpl, "PacketResponder") {
			template = tmpl
			break
		}
	}

	// Template should preserve static words like "PacketResponder", "for", "block", "terminating"
	// and replace only the dynamic parts with <*>
	expected := "PacketResponder <*> for block <*> terminating"
	if template != expected {
		t.Errorf("Paper compliance failed.\nExpected: %s\nGot: %s", expected, template)
	}
}

// TestFreqThresholdStrategies tests different frequency threshold calculation strategies
func TestFreqThresholdStrategies(t *testing.T) {
	testCases := []struct {
		name     string
		strategy FreqThresholdStrategy
		expected string
	}{
		{
			name:     "FreqMin (paper-compliant)",
			strategy: FreqMin,
			expected: "PacketResponder <*> for block <*> terminating",
		},
		{
			name:     "FreqAll (strictest)",
			strategy: FreqAll,
			expected: "PacketResponder <*> for block <*> terminating", // Only tokens in ALL events remain static
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewAWSOMLP()

			config := DefaultConfig()
			config.FreqThresholdStrategy = tc.strategy
			parser.WithConfig(config)

			results := parser.Parse(paperComplianceTestLogs)

			// Find the template for PacketResponder logs
			var template string
			for _, tmpl := range results {
				if strings.Contains(tmpl, "PacketResponder") || strings.Contains(tmpl, "<*>") {
					template = tmpl
					break
				}
			}

			if template != tc.expected {
				t.Errorf("%s failed.\nExpected: %s\nGot: %s", tc.name, tc.expected, template)
			}
		})
	}
}

// TestStrictAlphabeticalMatching tests the alphabetical token matching feature
func TestStrictAlphabeticalMatching(t *testing.T) {
	logs := []string{
		"Error in function processData",
		"Error in method processFile", // Different alphabetical tokens: method vs function, processFile vs processData
		"Warning in function processData",
	}

	testCases := []struct {
		name   string
		strict bool
	}{
		{
			name:   "Paper-compliant (no strict matching)",
			strict: false,
		},
		{
			name:   "Strict alphabetical matching",
			strict: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewAWSOMLP()

			config := DefaultConfig()
			config.StrictAlphabeticalMatching = tc.strict
			parser.WithConfig(config)

			results := parser.Parse(logs)
			patterns := parser.GetPatterns()

			if tc.strict {
				// With strict matching, first two logs should be in different patterns
				// because "function/method" and "processData/processFile" don't match exactly
				if len(patterns) < 2 {
					t.Errorf("Strict matching should create more patterns due to different alphabetical tokens")
				}
			} else {
				// Without strict matching, more grouping should occur based on similarity metric only
				t.Logf("Non-strict matching created %d patterns", len(patterns))
			}

			if len(results) != len(logs) {
				t.Errorf("Expected results for all %d logs, got %d", len(logs), len(results))
			}
		})
	}
}

// TestSmallGroupFrequencyAnalysis tests that small groups can undergo frequency analysis
func TestSmallGroupFrequencyAnalysis(t *testing.T) {
	// Use logs that would produce different frequency patterns
	// With 3 logs, "functionA" appears 2 times, "functionB" appears 1 time
	// With FreqMin strategy, minimum frequency = 1, so both meet threshold and remain static
	// But for this test, we need to use FreqAll to see the replacement
	logs := []string{
		"Error in functionA detected",
		"Error in functionA detected",
		"Error in functionB detected",
	}

	testCases := []struct {
		name              string
		applyFreqAnalysis bool
		expectStatic      string // What should remain static in the template
	}{
		{
			name:              "Apply freq analysis to small groups (paper-compliant)",
			applyFreqAnalysis: true,
			expectStatic:      "Error in <*> detected", // Should generalize varying tokens to <*>
		},
		{
			name:              "Skip freq analysis for small groups",
			applyFreqAnalysis: false,
			expectStatic:      "Error in functionA detected", // Should use first event as-is (no frequency analysis)
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewAWSOMLP()

			config := DefaultConfig()
			config.MinGroupSize = 4                // Groups have 3 events, so they're "small"
			config.FreqThresholdStrategy = FreqAll // Use FreqAll to ensure functionA/functionB are replaced
			config.ApplyFreqAnalysisToSmallGroups = tc.applyFreqAnalysis
			parser.WithConfig(config)

			results := parser.Parse(logs)

			// Find any template to check
			var template string
			for _, tmpl := range results {
				template = tmpl
				break
			}

			if template != tc.expectStatic {
				t.Errorf("Expected template: %s, got: %s", tc.expectStatic, template)
			}
		})
	}
}

// TestPaperComplianceWithMinFrequency tests that FreqMin correctly uses the minimum frequency
// from the group as described in the original paper
func TestPaperComplianceWithMinFrequency(t *testing.T) {
	parser := NewAWSOMLP()

	// Use paper-compliant configuration
	config := Config{
		MinGroupSize:          1,
		MaxPlaceholderRatio:   1.0,
		MinTemplateTokens:     0,
		FreqThresholdStrategy: FreqMin,
	}
	parser.WithConfig(config)

	// Test logs where tokens have different frequencies but same alphabetical letter count
	// "error" (5 letters), "alert" (5 letters), "debug" (5 letters) - all have same letter count
	testLogs := []string{
		"error occurred in module A",
		"error occurred in module B",
		"error occurred in module C",
		"alert occurred in module D",
		"alert occurred in module E",
		"debug occurred in module F",
	}

	_ = parser.Parse(testLogs)
	patterns := parser.GetPatterns()

	// Should create one pattern as all logs match similarity criteria
	if len(patterns) != 1 {
		t.Errorf("Expected 1 pattern, got %d", len(patterns))
	}

	// Get the template - with FreqMin strategy, tokens with frequency >= minimum frequency (1) are kept static
	// Since minimum frequency is 1, and "error", "occurred", "in", "module" all have frequency >= 1,
	// they should all be kept as static tokens
	template := patterns[0].Template

	// Verify frequency map
	freq := patterns[0].Frequency
	t.Logf("Frequency map: %v", freq)

	// With FreqMin strategy, the minimum frequency in this group is 1 (for "debug" and module letters)
	// So tokens with frequency >= 1 are kept static, tokens with frequency < 1 become <*>
	// Since all tokens have frequency >= 1, they should all be kept static
	// The template should be the first event since all its tokens meet the minimum frequency
	expectedTemplate := "error occurred in module A"

	if template != expectedTemplate {
		t.Errorf("Template mismatch.\nExpected: %s\nActual: %s", expectedTemplate, template)

		// Debug the actual frequency threshold calculation
		minFreqInGroup := 999
		for _, f := range freq {
			if f < minFreqInGroup {
				minFreqInGroup = f
			}
		}
		t.Logf("Actual minimum frequency in group: %d", minFreqInGroup)
		t.Logf("All frequencies: %v", freq)
	}

	// "occurred", "in", "module" should have frequency 6 (appear in all logs)
	// "error" should have frequency 3
	// "alert" should have frequency 2
	// "debug" should have frequency 1
	// Min frequency should be 1

	minFreq := len(patterns[0].Events)
	for _, f := range freq {
		if f < minFreq {
			minFreq = f
		}
	}

	if minFreq != 1 {
		t.Errorf("Expected minimum frequency to be 1, got %d", minFreq)
	}
}

// TestConfigValidation tests that new configuration fields are properly validated
func TestNewConfigValidation(t *testing.T) {
	parser := NewAWSOMLP()

	testCases := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid FreqPercentile",
			config: Config{
				FreqPercentile: 0.5,
			},
			expectError: false,
		},
		{
			name: "Invalid FreqPercentile too low",
			config: Config{
				FreqPercentile: -0.1,
			},
			expectError: true,
			errorMsg:    "FreqPercentile must be between 0 and 1",
		},
		{
			name: "Invalid FreqPercentile too high",
			config: Config{
				FreqPercentile: 1.1,
			},
			expectError: true,
			errorMsg:    "FreqPercentile must be between 0 and 1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := parser.WithConfig(tc.config)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tc.errorMsg)
				} else if !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tc.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
