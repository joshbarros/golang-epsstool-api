# golang-epsstool-api

## Overview

The `golang-epsstool-api` is a command-line interface (CLI) tool for exploring publicly available **Exploit Prediction Scoring System (EPSS)** data. The EPSS data describes the probability of exploitation for published vulnerabilities (CVEs). The tool can fetch and display EPSS scores, compare changes over time, and identify significant increases in scores.

This tool supports:

- Fetching EPSS scores for a given CVE
- Fetching EPSS scores for a CVE on a specific date
- Listing the top `N` CVEs based on EPSS scores
- Identifying CVEs with the highest score increase over a specified period
- Fetching CVEs above a defined EPSS score or percentile threshold
- Retrieving EPSS score time series data for specific CVEs

## Features

### Get Current EPSS Score
Fetch the current EPSS score and percentile for a given CVE.

```bash
go run cmd/epss/main.go score --cve CVE-2023-0001
```

### Get EPSS Score on a Specific Date
Fetch the EPSS score and percentile for a given CVE on a specific date.

```bash
go run cmd/epss/main.go score --cve CVE-2023-0001 --date 2024-01-01
```

### List Top `N` CVEs
Retrieve the top `N` CVEs based on their EPSS score.

```bash
go run cmd/epss/main.go top --limit 10
```

### Identify Highest EPSS Increases
Retrieve a list of the CVEs with the highest increase in EPSS score over the last `X` days.

```bash
go run cmd/epss/main.go highest --days 30 --limit 10
```

### Get Time Series Data
Retrieve the EPSS score time series for a specific CVE.

```bash
go run cmd/epss/main.go timeseries --cve CVE-2023-0001
```

### Get CVEs Above a Threshold
Fetch CVEs whose EPSS score or percentile is above a specified threshold.

```bash
go run cmd/epss/main.go threshold --threshold 0.95 --field epss
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
```

2. Navigate into the project directory:
```bash
cd golang-epsstool-api
```

3. Install dependencies:
The project does not use any external libraries for managing the data beyond the Go standard library. Ensure Go is installed and properly configured in your environment.

4. Run the application:
You can directly execute the CLI commands using `go run`:
```bash
go run cmd/epss/main.go <command> [flags]
```

## CLI Commands

### `score`
Fetches the EPSS score and percentile for a given CVE, optionally with a specific date.

Flags:
- `--cve`: The CVE ID (required)
- `--date`: The date (optional)

### `top`
Retrieves the top `N` CVEs based on EPSS score.

Flags:
- `--limit`: The number of CVEs to retrieve (default: 10)

### `highest`
Retrieves the CVEs with the highest increase in EPSS score over the last `X` days.

Flags:
- `--days`: Number of days to look back (default: 30)
- `--limit`: Number of CVEs to retrieve (default: 10)

### `threshold`
Fetches the CVEs whose EPSS score or percentile is above a given threshold.

Flags:
- `--threshold`: The minimum EPSS score or percentile (required)
- `--field`: Field to use for comparison (`epss` or `percentile`, required)

### `timeseries`
Retrieves time series EPSS data for a specific CVE.

Flags:
- `--cve`: The CVE ID (required)

## Architecture

1. **Domain Layer**: Contains core business logic and data models. This layer is independent of any external APIs or services.
   - `models`: Defines the `CVE` and `ScoreChange` domain objects.
   
2. **Application Layer**: Implements business use cases. Interacts with the domain layer to process data.
   - `repository`: Responsible for fetching data from external sources (EPSS API).

3. **Interface Layer**: Handles interactions with external systems like APIs or databases. In this case, the EPSS API is consumed.
   - `ports`: Defines the interfaces for repositories and services to abstract dependencies.

4. **Command Layer**: Contains the CLI logic. It parses user input, handles command-line arguments, and invokes the appropriate services.

### Separation of Concerns

Each layer is designed to ensure clear separation of concerns:
- **Domain Logic**: Independent of the API and data-fetching logic.
- **Data Access Logic**: Encapsulated within the repository.
- **CLI Logic**: Separate from business logic, only responsible for user interactions.

### Error Handling

Errors are handled gracefully across layers. Each function returns errors explicitly, and all error handling is centralized within the CLI layer to ensure proper feedback to the user.

### Dependencies

This project uses the Go standard library and avoids using unnecessary external dependencies. Dependencies include:
- **`net/http`**: For making HTTP requests to the EPSS API.
- **`encoding/json`**: For parsing JSON responses from the API.
- **`time`**: For handling date and time functions.
- **`stretchr/testify`** For testing functionalities on the project.
- **`urfave/cli`** For handling CLI commands with ease.

## Testing

The project includes unit tests for core functionality such as data fetching, score processing, and error handling. Run the tests using:
```bash
go test ./...
```

## Improvements & Refactoring (Planned)

- Implement test coverage for all major functions.
- Further decouple external services (such as the EPSS API) from business logic by introducing additional interfaces for easy mocking and testing.
- Refactor repetitive API fetching logic and improve error handling mechanisms across layers.
  
## Future Work

- **CSV Support**: Optionally support fetching the full EPSS dataset from the daily gzipped CSV.
- **Caching**: Introduce caching for API results to reduce the number of API calls.
- **Rate Limiting**: Add logic to handle rate-limiting from the EPSS API if needed.