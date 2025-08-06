package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	awsomlp "github.com/n0madic/awsom-lp"
)

// TemplateStats holds template and its frequency
type TemplateStats struct {
	Template string
	Count    int
}

func main() {
	// Define command-line flags
	var (
		inputFile           = flag.String("input", "", "Input log file (required)")
		csvColumn           = flag.String("column", "message", "CSV column name for log messages (default: message)")
		csvDelimiter        = flag.String("delimiter", ",", "CSV delimiter (default: comma)")
		headerRegex         = flag.String("header", "", "Header regex pattern (default, hdfs, syslog, java, or custom regex)")
		similarity          = flag.Float64("similarity", 1.0, "Minimum similarity threshold (0.0-1.0)")
		sortStrategy        = flag.String("sort", "none", "Sorting strategy: none, length, lexical, dyntokens")
		customRegex         = flag.String("regex", "", "Custom regex patterns for variables (comma-separated)")
		minGroupSize        = flag.Int("min-group", 3, "Minimum group size to generate template")
		maxPlaceholderRatio = flag.Float64("max-placeholders", 0.8, "Maximum ratio of placeholders in template (0.0-1.0)")
		minTemplateTokens   = flag.Int("min-tokens", 1, "Minimum number of non-placeholder tokens in template")
		showTemplates       = flag.Bool("templates", false, "Show only templates without counts")
		verbose             = flag.Bool("verbose", false, "Verbose output")
		maxLines            = flag.Int("max", 0, "Maximum number of lines to process (0 = all)")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "AWSOM-LP Log Parser CLI\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s -input <file> [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  Parse text log file:\n")
		fmt.Fprintf(os.Stderr, "    %s -input app.log\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Parse CSV file with specific column:\n")
		fmt.Fprintf(os.Stderr, "    %s -input logs.csv -column log_message\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Parse HDFS logs with specific header pattern:\n")
		fmt.Fprintf(os.Stderr, "    %s -input hdfs.log -header hdfs\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Parse with custom similarity and sorting:\n")
		fmt.Fprintf(os.Stderr, "    %s -input app.log -similarity 0.8 -sort length\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Filter low-quality templates:\n")
		fmt.Fprintf(os.Stderr, "    %s -input app.log -min-group 5 -max-placeholders 0.6 -min-tokens 2\n", os.Args[0])
	}

	flag.Parse()

	// Validate required input
	if *inputFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Open input file
	file, err := os.Open(*inputFile)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	// Read log lines based on file type
	var logLines []string
	if strings.HasSuffix(strings.ToLower(*inputFile), ".csv") {
		logLines, err = readCSVLogs(file, *csvColumn, *csvDelimiter)
		if err != nil {
			log.Fatalf("Error reading CSV file: %v", err)
		}
	} else {
		logLines, err = readTextLogs(file)
		if err != nil {
			log.Fatalf("Error reading text file: %v", err)
		}
	}

	// Apply max lines limit if specified
	if *maxLines > 0 && len(logLines) > *maxLines {
		logLines = logLines[:*maxLines]
	}

	if *verbose {
		fmt.Printf("Loaded %d log lines\n", len(logLines))
	}

	// Create parser
	parser := awsomlp.NewAWSOMLP()

	// Configure parser
	config := awsomlp.Config{
		MinSimilarity:       *similarity,
		MinGroupSize:        *minGroupSize,
		MaxPlaceholderRatio: *maxPlaceholderRatio,
		MinTemplateTokens:   *minTemplateTokens,
	}

	// Set header regex
	switch *headerRegex {
	case "default", "":
		config.HeaderRegex = awsomlp.DefaultHeaderRegex
	case "hdfs":
		config.HeaderRegex = awsomlp.HDFSHeaderRegex
	case "syslog":
		config.HeaderRegex = awsomlp.SyslogHeaderRegex
	case "java":
		config.HeaderRegex = awsomlp.JavaAppHeaderRegex
	default:
		// Treat as custom regex
		config.HeaderRegex = *headerRegex
	}

	// Set sorting strategy
	switch *sortStrategy {
	case "none":
		config.SortingStrategy = awsomlp.SortNone
	case "length":
		config.SortingStrategy = awsomlp.SortByLength
	case "lexical":
		config.SortingStrategy = awsomlp.SortLexical
	case "dyntokens":
		config.SortingStrategy = awsomlp.SortByDynTokens
	default:
		log.Fatalf("Invalid sorting strategy: %s", *sortStrategy)
	}

	// Add custom regex patterns
	if *customRegex != "" {
		config.CustomRegexes = strings.Split(*customRegex, ",")
		for i := range config.CustomRegexes {
			config.CustomRegexes[i] = strings.TrimSpace(config.CustomRegexes[i])
		}
	}

	// Apply configuration
	if err := parser.WithConfig(config); err != nil {
		log.Fatalf("Error configuring parser: %v", err)
	}

	// Parse logs
	if *verbose {
		fmt.Println("Parsing logs...")
	}
	results := parser.Parse(logLines)

	// Count template frequencies
	templateCount := make(map[string]int)
	for _, template := range results {
		templateCount[template]++
	}

	// Sort templates by frequency
	stats := make([]TemplateStats, 0, len(templateCount))
	for template, count := range templateCount {
		stats = append(stats, TemplateStats{
			Template: template,
			Count:    count,
		})
	}

	// Sort by count (descending) and then by template (ascending)
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Count != stats[j].Count {
			return stats[i].Count > stats[j].Count
		}
		return stats[i].Template < stats[j].Template
	})

	// Output results
	if *verbose {
		fmt.Printf("\nFound %d unique templates\n", len(stats))
		fmt.Println(strings.Repeat("=", 80))
	}

	for _, stat := range stats {
		if *showTemplates {
			fmt.Println(stat.Template)
		} else {
			fmt.Printf("[%d] %s\n", stat.Count, stat.Template)
		}
	}

	if *verbose {
		// Print summary statistics
		fmt.Println(strings.Repeat("=", 80))
		fmt.Printf("Total logs processed: %d\n", len(logLines))
		fmt.Printf("Unique templates: %d\n", len(stats))

		patterns := parser.GetPatterns()
		fmt.Printf("Pattern groups: %d\n", len(patterns))
	}
}

// readTextLogs reads log lines from a text file
func readTextLogs(file io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(file)

	// Increase buffer size for long lines
	const maxScanTokenSize = 1024 * 1024 // 1MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// readCSVLogs reads log lines from a CSV file
func readCSVLogs(file io.Reader, columnName string, delimiter string) ([]string, error) {
	var lines []string

	reader := csv.NewReader(file)
	if len(delimiter) > 0 {
		reader.Comma = rune(delimiter[0])
	}
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("error reading CSV header: %v", err)
	}

	// Find column index
	columnIndex := -1
	for i, col := range header {
		if strings.EqualFold(strings.TrimSpace(col), columnName) {
			columnIndex = i
			break
		}
	}

	if columnIndex == -1 {
		// If column not found, try to use the last column
		if strings.ToLower(columnName) == "message" {
			columnIndex = len(header) - 1
			fmt.Fprintf(os.Stderr, "Warning: Column '%s' not found, using column '%s' (index %d)\n",
				columnName, header[columnIndex], columnIndex)
		} else {
			return nil, fmt.Errorf("column '%s' not found in CSV header. Available columns: %v",
				columnName, header)
		}
	}

	// Read data rows
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip malformed rows
			continue
		}

		if len(record) > columnIndex {
			line := strings.TrimSpace(record[columnIndex])
			if line != "" {
				lines = append(lines, line)
			}
		}
	}

	return lines, nil
}
