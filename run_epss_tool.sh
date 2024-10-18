#!/bin/bash

# Run score command for CVE-2023-0001
echo "Running score command for CVE-2023-0001"
go run cmd/epss/main.go score --cve CVE-2023-0001

# Run score command with a specified date
echo "Running score command for CVE-2023-0001 with date 2024-10-17"
go run cmd/epss/main.go score --cve CVE-2023-0001 --date 2024-10-17

# Run date command for a specific date
echo "Running date command for 2024-10-17"
go run cmd/epss/main.go date --date 2024-10-17

# Run time series for a specific CVE
echo "Running time series command for CVE-2023-0001"
go run cmd/epss/main.go timeseries --cve CVE-2023-0001

# Run threshold for EPSS score greater than 0.95
echo "Running threshold command for EPSS score greater than 0.95"
go run cmd/epss/main.go threshold --threshold 0.95 --field epss

# Run threshold for percentile greater than 0.95
echo "Running threshold command for percentile greater than 0.95"
go run cmd/epss/main.go threshold --threshold 0.95 --field percentile

# Run highest EPSS scores over the last 30 days, limited to 10 results
echo "Running highest EPSS scores command for the last 30 days, limited to 10"
go run cmd/epss/main.go highest --days 30 --limit 10

echo "All commands executed successfully!"
