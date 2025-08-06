// Package awsomlp implements the AWSOM-LP (AWesome Structured Online Mining - Log Parser) algorithm
// based on the research paper "AWSOM-LP: An Effective Log Parsing Technique Using Pattern Recognition and Frequency Analysis"
//
// This package provides a powerful log parsing tool that leverages pattern recognition and frequency analysis
// to automatically extract templates from log data.
package awsomlp

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// SortingStrategy defines the strategy for sorting events in patterns
type SortingStrategy int

const (
	SortNone        SortingStrategy = iota // Use first event (original behavior)
	SortByLength                           // Sort by number of tokens
	SortLexical                            // Lexicographic sorting
	SortByDynTokens                        // Sort by number of dynamic tokens
)

// FreqThresholdStrategy defines how to calculate frequency threshold for static tokens
type FreqThresholdStrategy int

const (
	FreqMin        FreqThresholdStrategy = iota // Minimum frequency in group (paper-compliant)
	FreqMedian                                  // Median frequency
	FreqPercentile                              // User-defined percentile
	FreqAll                                     // All events (strictest, original implementation)
)

// Config holds configuration parameters for AWSOM-LP
type Config struct {
	MinSimilarity                  float64               // Similarity threshold (default 1.0 as in paper)
	SortingStrategy                SortingStrategy       // Strategy for sorting events in patterns (default SortNone)
	CustomRegexes                  []string              // Additional regex patterns for trivial variables
	HeaderRegex                    string                // Regex for extracting log header (default DefaultHeaderRegex)
	MinGroupSize                   int                   // Minimum group size to generate template (default 1 for paper compliance)
	MaxPlaceholderRatio            float64               // Maximum ratio of placeholders to total tokens (default 1.0 for paper compliance)
	MinTemplateTokens              int                   // Minimum number of non-placeholder tokens (default 1)
	FreqThresholdStrategy          FreqThresholdStrategy // Strategy for frequency threshold calculation (default FreqMin)
	FreqPercentile                 float64               // Percentile for FreqPercentile strategy (default 0.5)
	StrictAlphabeticalMatching     bool                  // Require exact alphabetical token matching (default false for paper compliance)
	ApplyFreqAnalysisToSmallGroups bool                  // Apply frequency analysis to groups < MinGroupSize (default true for paper compliance)
}

// DefaultConfig returns the default configuration that balances paper compliance with practicality
func DefaultConfig() Config {
	return Config{
		MinSimilarity:                  1.0,                // 100% similarity as in the paper
		SortingStrategy:                SortNone,           // Use first event (original behavior)
		CustomRegexes:                  []string{},         // No additional regexes
		HeaderRegex:                    DefaultHeaderRegex, // Universal header pattern
		MinGroupSize:                   1,                  // Allow all group sizes (paper-compliant)
		MaxPlaceholderRatio:            0.9,                // Slightly restrict to prevent degenerate templates
		MinTemplateTokens:              1,                  // Must have at least 1 real token
		FreqThresholdStrategy:          FreqMin,            // Minimum frequency strategy (paper-compliant)
		FreqPercentile:                 0.5,                // Default percentile (median)
		StrictAlphabeticalMatching:     false,              // Disable additional token matching (paper-compliant)
		ApplyFreqAnalysisToSmallGroups: true,               // Apply frequency analysis to all groups (paper-compliant)
	}
}

// LogEvent represents a processed log event
type LogEvent struct {
	Raw      string   // Original log string
	Content  string   // Content after header removal
	Tokens   []string // Tokens after splitting
	Template string   // Final template
}

// Pattern represents a group of similar log events
type Pattern struct {
	ID        int
	Events    []*LogEvent
	Template  string
	Frequency map[string]int // Token frequency in this group
}

// AWSOMLP represents the main parser structure
type AWSOMLP struct {
	patterns      []*Pattern
	headerRegex   *regexp.Regexp
	customRegexes []*regexp.Regexp // Only custom regexes from config
	config        Config           // Configuration parameters
}

// NewAWSOMLP creates a new parser instance with default configuration
func NewAWSOMLP() *AWSOMLP {
	lp := &AWSOMLP{
		patterns:      make([]*Pattern, 0),
		config:        DefaultConfig(),
		customRegexes: []*regexp.Regexp{}, // Start with empty custom regexes
	}

	return lp
}

// WithConfig applies configuration to the parser with validation
func (lp *AWSOMLP) WithConfig(config Config) error {
	// Start with default config and override with provided values
	defaultConfig := DefaultConfig()

	// Apply defaults for zero/empty values
	if config.MinSimilarity == 0 {
		config.MinSimilarity = defaultConfig.MinSimilarity
	}
	if config.HeaderRegex == "" {
		config.HeaderRegex = defaultConfig.HeaderRegex
	}
	if config.CustomRegexes == nil {
		config.CustomRegexes = defaultConfig.CustomRegexes
	}
	if config.MinGroupSize == 0 {
		config.MinGroupSize = defaultConfig.MinGroupSize
	}
	if config.MaxPlaceholderRatio == 0 {
		config.MaxPlaceholderRatio = defaultConfig.MaxPlaceholderRatio
	}
	if config.MinTemplateTokens == 0 {
		config.MinTemplateTokens = defaultConfig.MinTemplateTokens
	}
	if config.FreqPercentile == 0 {
		config.FreqPercentile = defaultConfig.FreqPercentile
	}

	// Validate configuration parameters
	if config.MinSimilarity < 0 || config.MinSimilarity > 1 {
		return fmt.Errorf("MinSimilarity must be between 0 and 1, got %f", config.MinSimilarity)
	}
	if config.MinGroupSize < 1 {
		return fmt.Errorf("MinGroupSize must be at least 1, got %d", config.MinGroupSize)
	}
	if config.MaxPlaceholderRatio < 0 || config.MaxPlaceholderRatio > 1 {
		return fmt.Errorf("MaxPlaceholderRatio must be between 0 and 1, got %f", config.MaxPlaceholderRatio)
	}
	if config.MinTemplateTokens < 0 {
		return fmt.Errorf("MinTemplateTokens must be non-negative, got %d", config.MinTemplateTokens)
	}
	if config.FreqPercentile < 0 || config.FreqPercentile > 1 {
		return fmt.Errorf("FreqPercentile must be between 0 and 1, got %f", config.FreqPercentile)
	}

	// Compile and set HeaderRegex
	re, err := regexp.Compile(config.HeaderRegex)
	if err != nil {
		return fmt.Errorf("invalid HeaderRegex: %v", err)
	}
	lp.headerRegex = re

	// Compile and store CustomRegexes
	lp.customRegexes = make([]*regexp.Regexp, 0, len(config.CustomRegexes))
	for _, pattern := range config.CustomRegexes {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid custom regex pattern %s: %v", pattern, err)
		}
		lp.customRegexes = append(lp.customRegexes, re)
	}

	// Apply configuration
	lp.config = config
	return nil
}

// chooseFreqThreshold calculates the frequency threshold based on the configured strategy
func (lp *AWSOMLP) chooseFreqThreshold(frequency map[string]int, groupSize int) int {
	switch lp.config.FreqThresholdStrategy {
	case FreqMin:
		// Paper-compliant: use actual minimum frequency in the group
		// According to the paper, tokens with frequency >= min(frequency) are static
		if len(frequency) == 0 {
			return 1
		}
		// Find the minimum frequency value
		minFreq := groupSize
		for _, freq := range frequency {
			if freq < minFreq {
				minFreq = freq
			}
		}
		return minFreq

	case FreqMedian:
		// Calculate median frequency
		if len(frequency) == 0 {
			return 1
		}
		frequencies := make([]int, 0, len(frequency))
		for _, freq := range frequency {
			frequencies = append(frequencies, freq)
		}
		sort.Ints(frequencies)
		mid := len(frequencies) / 2
		if len(frequencies)%2 == 0 {
			return (frequencies[mid-1] + frequencies[mid]) / 2
		}
		return frequencies[mid]

	case FreqPercentile:
		// Calculate frequency at specified percentile
		if len(frequency) == 0 {
			return 1
		}
		frequencies := make([]int, 0, len(frequency))
		for _, freq := range frequency {
			frequencies = append(frequencies, freq)
		}
		sort.Ints(frequencies)
		idx := int(float64(len(frequencies)-1) * lp.config.FreqPercentile)
		return frequencies[idx]

	case FreqAll:
		// Require token to appear in all events (strictest, original implementation)
		return groupSize

	default:
		return groupSize
	}
}

// Preprocess performs log event preprocessing
func (lp *AWSOMLP) Preprocess(logLine string) *LogEvent {
	event := &LogEvent{Raw: logLine}

	// Step 1: Header removal
	content := lp.removeHeader(logLine)

	// Step 2: Trivial variable replacement
	content = lp.replaceTrivialVariables(content)

	event.Content = content
	event.Tokens = strings.Fields(content)

	return event
}

// removeHeader removes header from log string
func (lp *AWSOMLP) removeHeader(logLine string) string {
	if lp.headerRegex == nil {
		return logLine
	}

	matches := lp.headerRegex.FindStringSubmatch(logLine)
	if len(matches) > 0 {
		// Assume content is in the last capture group
		for i := len(matches) - 1; i >= 0; i-- {
			if matches[i] != "" && matches[i] != logLine {
				return matches[i]
			}
		}
	}
	return logLine
}

// replaceTrivialVariables replaces trivial variables with <*>
func (lp *AWSOMLP) replaceTrivialVariables(content string) string {
	// Apply global trivial variable patterns
	for _, re := range trivialVarPatterns {
		content = re.ReplaceAllString(content, "<*>")
	}

	// Apply custom regexes
	for _, re := range lp.customRegexes {
		content = re.ReplaceAllString(content, "<*>")
	}

	return content
}

// patternRecognition groups similar log events
func (lp *AWSOMLP) patternRecognition(events []*LogEvent) {
	for _, event := range events {
		matched := false

		// Try to find existing pattern
		for _, pattern := range lp.patterns {
			if len(pattern.Events) == 0 {
				continue
			}

			// Compare with first event in pattern
			similarity := lp.calculateSimilarity(event, pattern.Events[0])

			// Debug: uncomment for debugging
			// fmt.Printf("DEBUG: Comparing event '%s' with pattern %d (first event: '%s'), similarity: %.3f, threshold: %.3f\n",
			//     event.Content, patternIdx, pattern.Events[0].Content, similarity, lp.config.MinSimilarity)

			if similarity >= lp.config.MinSimilarity {
				pattern.Events = append(pattern.Events, event)
				matched = true
				// Debug: uncomment for debugging
				// fmt.Printf("DEBUG: Event matched to pattern %d\n", patternIdx)
				break
			}
		}

		// If no suitable pattern found, create new one
		if !matched {
			newPattern := &Pattern{
				ID:        len(lp.patterns),
				Events:    []*LogEvent{event},
				Frequency: make(map[string]int),
			}
			lp.patterns = append(lp.patterns, newPattern)
			// Debug: uncomment for debugging
			// fmt.Printf("DEBUG: Created new pattern %d for event '%s'\n", newPattern.ID, event.Content)
		}
	}
}

// calculateSimilarity calculates similarity between two log events
// according to the formula from the document: similarity(L1,L2) = count(L1)/count(L2)
// Made symmetric to ensure consistent results regardless of event order
func (lp *AWSOMLP) calculateSimilarity(event1, event2 *LogEvent) float64 {
	count1 := lp.countAlphabeticalLetters(event1)
	count2 := lp.countAlphabeticalLetters(event2)

	if count1 == 0 || count2 == 0 {
		return 0
	}

	// Check that alphabetical tokens match (if strict matching is enabled)
	if lp.config.StrictAlphabeticalMatching {
		alphaTokens1 := lp.getAlphabeticalTokens(event1)
		alphaTokens2 := lp.getAlphabeticalTokens(event2)

		// If sets of alphabetical tokens are different, similarity is 0
		if !lp.alphabeticalTokensMatch(alphaTokens1, alphaTokens2) {
			return 0
		}
	}

	// Make similarity symmetric: use the smaller count as numerator
	// This ensures similarity is always <= 1.0 and symmetric
	minCount := count1
	maxCount := count2
	if count2 < count1 {
		minCount = count2
		maxCount = count1
	}

	return float64(minCount) / float64(maxCount)
}

// countAlphabeticalLetters counts the number of letters in alphabetical tokens
func (lp *AWSOMLP) countAlphabeticalLetters(event *LogEvent) int {
	count := 0
	for _, token := range event.Tokens {
		if lp.isAlphabeticalToken(token) {
			for _, r := range token {
				if unicode.IsLetter(r) {
					count++
				}
			}
		}
	}
	return count
}

// getAlphabeticalTokens returns only alphabetical tokens
func (lp *AWSOMLP) getAlphabeticalTokens(event *LogEvent) []string {
	var alphaTokens []string
	for _, token := range event.Tokens {
		if lp.isAlphabeticalToken(token) {
			alphaTokens = append(alphaTokens, token)
		}
	}
	return alphaTokens
}

// alphabeticalTokensMatch checks if alphabetical tokens match
func (lp *AWSOMLP) alphabeticalTokensMatch(tokens1, tokens2 []string) bool {
	if len(tokens1) != len(tokens2) {
		return false
	}
	for i := range tokens1 {
		if tokens1[i] != tokens2[i] {
			return false
		}
	}
	return true
}

// isAlphabeticalToken checks if token is alphabetical
// (contains no digits and special characters, except <*>)
func (lp *AWSOMLP) isAlphabeticalToken(token string) bool {
	if token == "<*>" {
		return false
	}

	for _, r := range token {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return len(token) > 0
}

// sortEventsInPattern sorts events in pattern according to the configured strategy
func (lp *AWSOMLP) sortEventsInPattern(events []*LogEvent) []*LogEvent {
	switch lp.config.SortingStrategy {
	case SortByLength:
		return lp.sortByLength(events)
	case SortLexical:
		return lp.sortLexically(events)
	case SortByDynTokens:
		return lp.sortByDynamicTokenCount(events)
	default: // SortNone
		return events
	}
}

// sortByLength sorts events by the number of tokens (ascending)
func (lp *AWSOMLP) sortByLength(events []*LogEvent) []*LogEvent {
	sorted := make([]*LogEvent, len(events))
	copy(sorted, events)

	sort.Slice(sorted, func(i, j int) bool {
		// Primary sort by token count
		if len(sorted[i].Tokens) != len(sorted[j].Tokens) {
			return len(sorted[i].Tokens) < len(sorted[j].Tokens)
		}
		// Secondary sort by content for determinism
		return sorted[i].Content < sorted[j].Content
	})

	return sorted
}

// sortLexically sorts events lexicographically by content
func (lp *AWSOMLP) sortLexically(events []*LogEvent) []*LogEvent {
	sorted := make([]*LogEvent, len(events))
	copy(sorted, events)

	sort.Slice(sorted, func(i, j int) bool {
		// Primary sort by content
		if sorted[i].Content != sorted[j].Content {
			return sorted[i].Content < sorted[j].Content
		}
		// Secondary sort by raw string for determinism
		return sorted[i].Raw < sorted[j].Raw
	})

	return sorted
}

// sortByDynamicTokenCount sorts events by the number of dynamic tokens (non-alphabetical)
func (lp *AWSOMLP) sortByDynamicTokenCount(events []*LogEvent) []*LogEvent {
	sorted := make([]*LogEvent, len(events))
	copy(sorted, events)

	// Function to count dynamic tokens
	countDynamicTokens := func(event *LogEvent) int {
		count := 0
		for _, token := range event.Tokens {
			if !lp.isAlphabeticalToken(token) {
				count++
			}
		}
		return count
	}

	sort.Slice(sorted, func(i, j int) bool {
		// Primary sort by dynamic token count
		dynCount1 := countDynamicTokens(sorted[i])
		dynCount2 := countDynamicTokens(sorted[j])
		if dynCount1 != dynCount2 {
			return dynCount1 < dynCount2
		}
		// Secondary sort by content for determinism
		return sorted[i].Content < sorted[j].Content
	})

	return sorted
}

// frequencyAnalysis applies frequency analysis to each pattern
func (lp *AWSOMLP) frequencyAnalysis() {
	for _, pattern := range lp.patterns {
		if len(pattern.Events) == 0 {
			continue
		}

		// For small groups: apply frequency analysis based on configuration
		if len(pattern.Events) < lp.config.MinGroupSize && !lp.config.ApplyFreqAnalysisToSmallGroups {
			// Sort events in pattern if sorting strategy is enabled
			if lp.config.SortingStrategy != SortNone {
				pattern.Events = lp.sortEventsInPattern(pattern.Events)
			}

			// Use preprocessed content of first event as template
			pattern.Template = pattern.Events[0].Content

			// Apply template to all events in the group
			for _, event := range pattern.Events {
				event.Template = pattern.Template
			}
			continue
		}

		// For large groups: apply full frequency analysis
		// Sort events in pattern if sorting strategy is enabled
		if lp.config.SortingStrategy != SortNone {
			pattern.Events = lp.sortEventsInPattern(pattern.Events)
		}

		// Count frequency of each token in the group
		pattern.Frequency = make(map[string]int)
		for _, event := range pattern.Events {
			for _, token := range event.Tokens {
				pattern.Frequency[token]++
			}
		}

		// Frequency threshold: calculate based on configured strategy
		freqThreshold := lp.chooseFreqThreshold(pattern.Frequency, len(pattern.Events))

		// Generate template based on frequency using first event (potentially sorted)
		template := lp.generateTemplate(pattern.Events[0], pattern.Frequency, freqThreshold)

		// Check if template has too many placeholders - if so, use simpler template
		if lp.hasExcessivePlaceholders(template) {
			// Fallback to preprocessed content
			template = pattern.Events[0].Content
		}

		pattern.Template = template

		// Apply template to all events in the group
		for _, event := range pattern.Events {
			event.Template = pattern.Template
		}
	}
}

// hasExcessivePlaceholders checks if template has too many placeholders
func (lp *AWSOMLP) hasExcessivePlaceholders(template string) bool {
	tokens := strings.Fields(template)
	if len(tokens) == 0 {
		return false
	}

	placeholderCount := 0
	for _, token := range tokens {
		if token == "<*>" {
			placeholderCount++
		}
	}

	placeholderRatio := float64(placeholderCount) / float64(len(tokens))
	return placeholderRatio > lp.config.MaxPlaceholderRatio
}

// generateTemplate generates template based on frequency analysis
func (lp *AWSOMLP) generateTemplate(event *LogEvent, frequency map[string]int, freqThreshold int) string {
	var templateTokens []string

	for _, token := range event.Tokens {
		if token == "<*>" {
			templateTokens = append(templateTokens, token)
		} else if frequency[token] >= freqThreshold {
			// Static token (appears frequently enough)
			templateTokens = append(templateTokens, token)
		} else {
			// Dynamic token (appears infrequently - likely variable)
			templateTokens = append(templateTokens, "<*>")
		}
	}

	return strings.Join(templateTokens, " ")
}

// replaceRemainingNumericalVariables replaces remaining numerical variables
func (lp *AWSOMLP) replaceRemainingNumericalVariables() {
	for _, pattern := range lp.patterns {
		for _, re := range numericalPatterns {
			// Replace in template
			pattern.Template = re.ReplaceAllStringFunc(pattern.Template, func(match string) string {
				// Preserve spaces/brackets
				prefix := ""
				suffix := ""
				content := match

				if strings.HasPrefix(match, " ") {
					prefix = " "
					content = content[1:]
				}
				if strings.HasSuffix(match, " ") {
					suffix = " "
					content = content[:len(content)-1]
				}
				if strings.HasPrefix(content, "(") && strings.HasSuffix(content, ")") {
					return "(<*>)"
				}
				if strings.HasPrefix(content, "[") && strings.HasSuffix(content, "]") {
					return "[<*>]"
				}

				return prefix + "<*>" + suffix
			})
		}

		// Update templates for all events in pattern
		for _, event := range pattern.Events {
			event.Template = pattern.Template
		}
	}
}

// Parse performs complete parsing process
func (lp *AWSOMLP) Parse(logLines []string) map[string]string {
	// Input validation
	if logLines == nil {
		return make(map[string]string)
	}

	// Step 1: Preprocessing
	events := make([]*LogEvent, 0, len(logLines))
	for _, line := range logLines {
		if line = strings.TrimSpace(line); line != "" {
			// Limit individual line length to prevent ReDoS attacks
			const maxLineLength = 10000 // 10KB per line
			if len(line) > maxLineLength {
				line = line[:maxLineLength]
			}
			event := lp.Preprocess(line)
			events = append(events, event)
		}
	}

	// Step 2: Pattern recognition
	lp.patternRecognition(events)

	// Step 3: Frequency analysis
	lp.frequencyAnalysis()

	// Step 4: Replace remaining numerical variables
	lp.replaceRemainingNumericalVariables()

	// Return results - every log must have a result
	results := make(map[string]string)
	for _, event := range events {
		template := strings.TrimSpace(event.Template)
		if template == "" {
			// Fallback to preprocessed content if no template was generated
			template = strings.TrimSpace(event.Content)
			if template == "" {
				template = strings.TrimSpace(event.Raw) // Ultimate fallback
			}
		}
		results[event.Raw] = template
	}

	return results
}

// GetTemplates returns all unique templates
func (lp *AWSOMLP) GetTemplates() []string {
	templateMap := make(map[string]bool)
	templates := make([]string, 0)

	for _, pattern := range lp.patterns {
		template := strings.TrimSpace(pattern.Template)
		if lp.isValidTemplate(template) && !templateMap[template] {
			templateMap[template] = true
			templates = append(templates, template)
		}
	}

	sort.Strings(templates)
	return templates
}

// isValidTemplate checks if template is meaningful (not empty or only placeholders)
func (lp *AWSOMLP) isValidTemplate(template string) bool {
	if template == "" {
		return false
	}

	// Count non-placeholder tokens
	tokens := strings.Fields(template)
	if len(tokens) == 0 {
		return false
	}

	realTokens := 0
	for _, token := range tokens {
		if token != "<*>" {
			realTokens++
		}
	}

	// Must have at least MinTemplateTokens real tokens
	return realTokens >= lp.config.MinTemplateTokens
}

// GetPatterns returns all patterns with their statistics
func (lp *AWSOMLP) GetPatterns() []*Pattern {
	return lp.patterns
}
