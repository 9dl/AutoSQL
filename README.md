# AutoSQL - Automated SQLMap Runner

**AutoSQL** is an automated tool that runs SQLMap to scan URLs for SQL injection vulnerabilities. It automatically downloads SQLMap if not already present and runs SQLMap in a non-interactive mode. The tool supports scanning both single URLs and multiple URLs loaded from a file.

## Requirements

Before running AutoSQL, ensure the following are installed on your system:

- **Python**: Required to run SQLMap.
- **Git**: Required to clone the SQLMap repository.

You can download Python from [python.org](https://www.python.org/downloads/) and Git from [git-scm.com](https://git-scm.com/).

## Setup

### 1. Clone this repository (if you haven't already):

```bash
git clone https://github.com/9dl/AutoSQL.git
cd AutoSQL
```

### 2. Install Dependencies

Make sure **Python** and **Git** are installed on your machine.

AutoSQL will automatically download SQLMap the first time you run it if SQLMap is not found in the expected path (`./sqlmap/sqlmap.py`).

### 3. Run the Application

AutoSQL will download SQLMap if needed and allow you to start scanning URLs for SQL injection vulnerabilities.

```bash
go run main.go -url "http://example.com/vulnerable_page?id=" -risk 3 -level 5
```

### 4. Configuration Options

AutoSQL allows customization via command-line flags. Here are the available options:

- `-risk`: Set the SQLMap risk level (default: `3`).
- `-level`: Set the SQLMap level (default: `3`).
- `-threads`: Number of concurrent threads for URL scanning (default: `20`).
- `-threads_sql`: Number of threads for SQLMap database dumping (max: `10`, default: `10`).
- `-debug`: Enable debug output for detailed SQLMap logs.
- `-url`: Test a single URL for vulnerabilities.
- `-default-single`: Use predefined settings for a single URL (Risk: 3, Level: 5).
- `-default-multi`: Use predefined settings for multiple URLs (Risk: 2, Level: 3, Threads: 30, SQL Threads: 10).

### Example Usage

#### Scan a Single URL

To scan a single URL for SQL injection vulnerabilities:

```bash
go run main.go -url "http://example.com/vulnerable_page" -risk 3 -level 5
```

This command will scan the provided URL and dump relevant details if a vulnerability is found.

#### Scan Multiple URLs from a File

To scan multiple URLs loaded from a file:

```bash
go run main.go -default-multi
```

The program will prompt you to enter a file path containing a list of URLs (one per line). It will then begin scanning each URL concurrently.

#### Default Settings for Single URL Scan

To use the predefined settings for a single URL with Risk 3 and Level 5:

```bash
go run main.go -default-single -url "http://example.com/vulnerable_page"
```

#### Default Settings for Multiple URL Scan

To use the predefined settings for scanning multiple URLs with Risk 2, Level 3, and 30 threads:

```bash
go run main.go -default-multi
```

### License

AutoSQL is licensed under CC0 1.0 Universal. The SQLMap project is licensed under the GNU General Public License (GPL). For more details, please refer to the [SQLMap GitHub repository](https://github.com/sqlmapproject/sqlmap).