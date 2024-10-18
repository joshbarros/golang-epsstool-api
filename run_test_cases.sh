#!/bin/bash

# Test 1: Run score command for a specific CVE
echo "Test 1 of 7: Running score command for CVE-2023-0001"
go run cmd/epss/main.go score --cve CVE-2023-0001

# Test 2: Run score command with a specific date for CVE-2023-0001
echo "Test 2 of 7: Running score command for CVE-2023-0001 with date 2024-10-17"
go run cmd/epss/main.go score --cve CVE-2023-0001 --date 2024-10-17

# Test 3: Run top CVEs command, limited to 10
echo "Test 3 of 7: Running top 10 CVEs command"
go run cmd/epss/main.go top --limit 10

# Test 4: Run command for CVEs with the highest EPSS increases over the last 30 days
echo "Test 4 of 7: Running command to fetch highest EPSS increases over the last 30 days"
go run cmd/epss/main.go highest --days 30 --limit 10

# Test 5: Run time series command for a specific CVE
echo "Test 5 of 7: Running time series command for CVE-2023-0001"
go run cmd/epss/main.go timeseries --cve CVE-2023-0001

# Test 6: Run threshold command for CVEs with an EPSS score above 0.95
echo "Test 6 of 7: Running threshold command for EPSS score greater than 0.95"
go run cmd/epss/main.go threshold --threshold 0.95 --field epss

# Test 7: Run threshold command for CVEs with a percentile above 0.95
echo "Test 7 of 7: Running threshold command for percentile greater than 0.95"
go run cmd/epss/main.go threshold --threshold 0.95 --field percentile

echo "All test cases executed!"
