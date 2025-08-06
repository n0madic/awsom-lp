# AWSOM-LP: Effective Log Parsing Library

A powerful Go library implementing the AWSOM-LP (AWesome Structured Online Mining - Log Parser) algorithm for automated log parsing using pattern recognition and frequency analysis.

Based on the research paper: *"AWSOM-LP: An Effective Log Parsing Technique Using Pattern Recognition and Frequency Analysis"*

## Features

✨ **Pattern Recognition**: Automatically groups similar log events using text similarity

🔍 **Frequency Analysis**: Distinguishes static vs dynamic tokens using frequency analysis

⚙️ **Flexible Configuration**: Customizable similarity thresholds, sorting strategies, and regex patterns

🚀 **High Performance**: Efficient parsing with benchmark tests showing ~2ms per parse operation

📊 **Multiple Sorting Strategies**: Deterministic results with various event sorting options

🧪 **Well Tested**: 93.8% test coverage with comprehensive unit and benchmark tests

🖥️ **CLI Tool**: Ready-to-use command-line utility for parsing log files

## Installation

### Library
```bash
go get github.com/n0madic/awsom-lp
```

### CLI Tool
```bash
# Install from source
go install github.com/n0madic/awsom-lp/cmd/awsom-lp@latest
awsom-lp -h
```

## Quick Start

### Library Usage

```go
package main

import (
    "fmt"
    awsomlp "github.com/n0madic/awsom-lp"
)

func main() {
    // Create parser with default configuration
    parser := awsomlp.NewAWSOMLP()

    // Sample log data
    logs := []string{
        "2023-01-15 14:30:45 INFO: User login successful for user123",
        "2023-01-15 14:31:02 INFO: User login successful for user456",
        "2023-01-15 14:31:15 ERROR: Failed to connect to database",
    }

    // Parse logs
    results := parser.Parse(logs)

    // Get generated templates
    templates := parser.GetTemplates()

    for _, template := range templates {
        fmt.Println("Template:", template)
    }

    // Output like this:
    // Template: Failed to connect to database
    // Template: User login successful for <*>
}
```

### CLI Usage

```bash
# Parse text log file
awsom-lp -input app.log

# Parse with verbose output
awsom-lp -input app.log -verbose

# Parse CSV file with specific column
awsom-lp -input logs.csv -column msg

# Parse with custom configuration
awsom-lp -input app.log -similarity 0.8 -sort lexical -verbose

# Show only templates (without frequency counts)
awsom-lp -input app.log -templates
```

**Example Output:**
```
[3] <*> INFO: User <*> logged in successfully from <*>
[2] <*> ERROR: Failed to connect to database server <*>
[1] <*> INFO: Processing request ID <*> for user <*>
```

## Configuration

### Pre-defined Header Patterns

```go
awsomlp.DefaultHeaderRegex  // Universal pattern for most logs
awsomlp.HDFSHeaderRegex     // HDFS format from research paper
awsomlp.SyslogHeaderRegex   // Standard syslog format
awsomlp.JavaAppHeaderRegex  // Java application logging
```

### Sorting Strategies for Stable Results

```go
awsomlp.SortNone        // Use first event (original behavior)
awsomlp.SortByLength    // Sort by number of tokens
awsomlp.SortLexical     // Lexicographic sorting
awsomlp.SortByDynTokens // Sort by dynamic token count
```

### Frequency Threshold Strategies

```go
awsomlp.FreqMin        // True minimum frequency (paper-compliant, default)
awsomlp.FreqMedian     // Median frequency threshold
awsomlp.FreqPercentile // User-defined percentile
awsomlp.FreqAll        // Strictest - tokens must appear in ALL events
```

### Custom Configuration Example

```go
parser := awsomlp.NewAWSOMLP()

config := awsomlp.Config{
    MinSimilarity:   0.8,                      // 80% similarity threshold
    SortingStrategy: awsomlp.SortByLength,     // Sort for stability
    HeaderRegex:     awsomlp.HDFSHeaderRegex,  // HDFS log format
    CustomRegexes:   []string{`user\d+`},      // Custom variable patterns
}

err := parser.WithConfig(config)
if err != nil {
    log.Fatal(err)
}

results := parser.Parse(logLines)
```

### Partial Configuration (Recommended)

```go
parser := awsomlp.NewAWSOMLP()

// Only specify what you want to change - rest uses defaults
config := awsomlp.Config{
    SortingStrategy: awsomlp.SortLexical, // Just change sorting
}

parser.WithConfig(config)
```

## Paper Compliance & Configuration Guide

### Algorithm Compliance

By default, AWSOM-LP closely follows the original research paper with minor practical improvements:

- **Frequency Threshold**: Uses true minimum frequency (paper-compliant with FreqMin strategy)
- **Alphabetical Matching**: Disabled (uses only similarity metric from paper)
- **Small Group Analysis**: All groups undergo frequency analysis (MinGroupSize = 1)
- **Placeholder Limits**: Slightly restricted (0.9) to prevent completely degenerate templates

### Strict Paper Compliance Configuration

For maximum compliance with the original paper algorithm:

```go
parser := awsomlp.NewAWSOMLP()

config := awsomlp.Config{
    MinSimilarity:                  1.0,     // 100% similarity as in paper
    MinGroupSize:                   1,       // Allow single-event groups
    MaxPlaceholderRatio:            1.0,     // No placeholder restrictions
    MinTemplateTokens:              0,       // No minimum token requirements
    FreqThresholdStrategy:          awsomlp.FreqMin, // True minimum frequency
    ApplyFreqAnalysisToSmallGroups: true,    // Analyze all groups
}

parser.WithConfig(config)
```

### Comparison: Paper Requirements vs DefaultConfig()

| Aspect | Paper Requirement | DefaultConfig() | Rationale |
|--------|------------------|-----------------|-----------|
| Similarity Threshold | 1.0 (100%) | 1.0 | Paper-compliant |
| Frequency Threshold | True minimum | FreqMin (true min) | Paper-compliant |
| Min Group Size | 1 | 1 | Paper-compliant |
| Max Placeholder Ratio | No limit | 0.9 | Slight practical improvement |
| Min Template Tokens | No requirement | 1 | Minimal practical constraint |
| Alphabetical Matching | Similarity only | Disabled | Paper-compliant |

### Advanced Configuration Options

#### Frequency Threshold Strategies

Control how tokens are classified as static vs. dynamic:

```go
type FreqThresholdStrategy int

const (
    FreqMin        // True minimum frequency (paper-compliant, default)
    FreqMedian     // Median frequency threshold
    FreqPercentile // User-defined percentile
    FreqAll        // Strictest - tokens must appear in ALL events
)
```

**Usage Examples:**

```go
// Paper-compliant (default)
config := awsomlp.DefaultConfig() // Uses FreqMin

// Production optimization - stricter templates
config := awsomlp.Config{
    FreqThresholdStrategy: awsomlp.FreqAll, // Most conservative
}

// Custom percentile threshold
config := awsomlp.Config{
    FreqThresholdStrategy: awsomlp.FreqPercentile,
    FreqPercentile:       0.8, // 80th percentile
}
```

#### Pattern Matching Options

```go
config := awsomlp.Config{
    // Enable stricter alphabetical token matching
    StrictAlphabeticalMatching: true, // Default: false (paper-compliant)

    // Control small group behavior
    MinGroupSize: 3,                           // Groups with fewer events
    ApplyFreqAnalysisToSmallGroups: true,      // Default: true (paper-compliant)

    // Template quality controls
    MaxPlaceholderRatio: 0.8,  // Max 80% placeholders (default: 1.0)
    MinTemplateTokens: 1,      // Minimum real tokens required
}
```

### Configuration Recommendations

#### For Research/Academic Use
```go
parser := awsomlp.NewAWSOMLP()
// Use defaults - paper-compliant settings
```

#### For Production Log Analysis
```go
config := awsomlp.Config{
    FreqThresholdStrategy:      awsomlp.FreqAll,     // Stricter templates
    StrictAlphabeticalMatching: true,                // More precise grouping
    MaxPlaceholderRatio:        0.7,                 // Limit over-generalization
    SortingStrategy:            awsomlp.SortLexical, // Deterministic results
}
```

#### For High-Volume Systems
```go
config := awsomlp.Config{
    MinGroupSize: 5,                                 // Ignore rare events
    ApplyFreqAnalysisToSmallGroups: false,           // Skip analysis for small groups
    FreqThresholdStrategy:          awsomlp.FreqAll, // Conservative templates
}
```

#### For HDFS Logs (Original Paper Dataset)
```go
config := awsomlp.Config{
    HeaderRegex: awsomlp.HDFSHeaderRegex,
    // Other settings remain paper-compliant
}
```

## Algorithm Overview

AWSOM-LP follows a 4-step process:

1. **Preprocessing**: Removes headers and replaces common variables (IPs, timestamps, etc.)
2. **Pattern Recognition**: Groups similar events using 100% alphabetical token similarity
3. **Frequency Analysis**: Identifies static vs dynamic tokens within each group
4. **Numerical Variable Replacement**: Final cleanup of remaining numerical patterns (including identifiers like `blk_123456789`)

## API Reference

### Core Methods

- `NewAWSOMLP() *AWSOMLP` - Create new parser with defaults
- `WithConfig(config Config) error` - Apply configuration with validation
- `Parse(logLines []string) map[string]string` - Parse logs and return templates
- `GetTemplates() []string` - Get all unique templates (sorted)
- `GetPatterns() []*Pattern` - Get all patterns with statistics

### Types

```go
type Config struct {
    MinSimilarity                 float64               // Similarity threshold (default: 1.0)
    SortingStrategy               SortingStrategy       // Event sorting strategy
    CustomRegexes                 []string              // Additional regex patterns
    HeaderRegex                   string                // Header extraction pattern
    MinGroupSize                  int                   // Minimum group size for template generation
    MaxPlaceholderRatio           float64               // Maximum ratio of placeholders to tokens
    MinTemplateTokens             int                   // Minimum number of non-placeholder tokens
    FreqThresholdStrategy         FreqThresholdStrategy // Frequency threshold calculation strategy
    FreqPercentile                float64               // Percentile for FreqPercentile strategy
    StrictAlphabeticalMatching    bool                  // Require exact alphabetical token matching
    ApplyFreqAnalysisToSmallGroups bool                 // Apply frequency analysis to small groups
}

type LogEvent struct {
    Raw      string   // Original log string
    Content  string   // Content after preprocessing
    Tokens   []string // Tokenized content
    Template string   // Generated template
}
```

## CLI Tool Features

The CLI tool provides comprehensive log parsing capabilities:

### Command-line Options

```bash
Usage: awsom-lp -input <file> [options]

Options:
  -input string          Input log file (required)
  -column string         CSV column name for log messages (default: "message")
  -delimiter string      CSV delimiter (default: ",")
  -header string         Header regex pattern (default, hdfs, syslog, java, or custom)
  -similarity float      Minimum similarity threshold 0.0-1.0 (default: 1.0)
  -sort string           Sorting strategy: none, length, lexical, dyntokens (default: "none")
  -regex string          Custom regex patterns for variables (comma-separated)
  -templates             Show only templates without counts
  -verbose               Verbose output with statistics
  -max int              Maximum number of lines to process (0 = all)
```

### Supported Input Formats

- **Text files** - Plain text log files (`.log`, `.txt`, etc.)
- **CSV files** - CSV files with configurable column selection and delimiter
- **Any delimiter** - Configurable CSV delimiter (comma, semicolon, tab, etc.)

### Output Formats

- **Frequency-sorted templates** (default): `[count] template`
- **Templates only**: Just the templates without frequency counts
- **Verbose mode**: Additional statistics and processing information

## Testing

Run the comprehensive test suite:

```bash
go test -v                # Verbose test output
go test -cover           # Test coverage report
go test -bench=.         # Benchmark tests
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `go test -v`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Citation

If you use this library in research, please cite the original paper:

```bibtex
@article{awsom-lp,
  title={AWSOM-LP: An Effective Log Parsing Technique Using Pattern Recognition and Frequency Analysis},
  author={Sedki, Issam and Hamou-Lhadj, Abdelwahab and Ait-Mohamed, Otmane},
  journal={IEEE Transactions on Software Engineering},
  year={2023}
}
```
