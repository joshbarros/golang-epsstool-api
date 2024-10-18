package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joshbarros/golang-epsstool-api/internal/infrastructure/repository"
	"github.com/urfave/cli/v2"
)

// handleGetScore retrieves the EPSS score for a given CVE ID and optional date.
func handleGetScore(c *cli.Context) error {
	cveID := c.String("cve")
	dateStr := c.String("date")

	repo := repository.NewAPIRepository("https://api.first.org/data/v1/epss")

	var date time.Time
	var err error
	if dateStr == "" {
		date = time.Now()
	} else {
		date, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			return fmt.Errorf("invalid date format: %w", err)
		}
	}

	score, err := repo.GetCVEScore(cveID, date.Format("2006-01-02"))
	if err != nil {
		return fmt.Errorf("failed to get CVE score: %w", err)
	}

	fmt.Printf("CVE ID: %s\n", score.ID)
	fmt.Printf("EPSS Score: %f\n", score.EPSSScore)
	fmt.Printf("Percentile: %f\n", score.Percentile)
	fmt.Printf("Date: %s\n", score.Date)

	return nil
}

// handleTopNCVEs retrieves the top N CVEs based on EPSS score.
func handleTopNCVEs(c *cli.Context) error {
	nStr := c.String("n")
	n, err := strconv.Atoi(nStr)
	if err != nil {
		return fmt.Errorf("invalid n value: %w", err)
	}

	repo := repository.NewAPIRepository("https://api.first.org/data/v1/epss")
	topCVEs, err := repo.GetTopNCVEs(n)
	if err != nil {
		return fmt.Errorf("failed to get top N CVEs: %w", err)
	}

	for _, cve := range topCVEs {
		fmt.Printf("CVE ID: %s, EPSS Score: %f, Percentile: %f, Date: %s\n", cve.ID, cve.EPSSScore, cve.Percentile, cve.Date)
	}

	return nil
}

// handleHighestIncreases retrieves the top N CVEs with the highest increase in EPSS score within the last X days.
func handleHighestIncreases(c *cli.Context) error {
	daysStr := c.String("days")
	limitStr := c.String("limit")

	days, err := strconv.Atoi(daysStr)
	if err != nil {
		return fmt.Errorf("invalid days value: %w", err)
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		return fmt.Errorf("invalid limit value: %w", err)
	}

	repo := repository.NewAPIRepository("https://api.first.org/data/v1/epss")
	highestIncreases, err := repo.GetHighestIncreases(days, limit)
	if err != nil {
		return fmt.Errorf("failed to get highest increases: %w", err)
	}

	for _, increase := range highestIncreases {
		fmt.Printf("CVE ID: %s, Date: %s, Score Change: %f\n", increase.CVE, increase.Date, increase.ScoreChange)
	}

	return nil
}

// handleGetCVEsForDate retrieves CVEs for a specific date.
func handleGetCVEsForDate(c *cli.Context) error {
	dateStr := c.String("date")
	repo := repository.NewAPIRepository("https://api.first.org/data/v1/epss")
	cves, err := repo.GetCVEsForDate(dateStr)
	if err != nil {
		return fmt.Errorf("failed to get CVEs for date: %w", err)
	}
	for _, cve := range cves {
		fmt.Printf("CVE ID: %s, EPSS Score: %f, Percentile: %f, Date: %s\n", cve.ID, cve.EPSSScore, cve.Percentile, cve.Date)
	}
	return nil
}

// handleGetTimeSeries retrieves time series data for a given CVE ID.
func handleGetTimeSeries(c *cli.Context) error {
	cveID := c.String("cve")
	repo := repository.NewAPIRepository("https://api.first.org/data/v1/epss")
	cves, err := repo.GetTimeSeries(cveID)
	if err != nil {
		return fmt.Errorf("failed to get time series for CVE: %w", err)
	}
	for _, cve := range cves {
		fmt.Printf("CVE ID: %s, EPSS Score: %f, Percentile: %f, Date: %s\n", cve.ID, cve.EPSSScore, cve.Percentile, cve.Date)
	}
	return nil
}

// handleGetCVEsAboveThreshold retrieves CVEs above a specified threshold for a given field (epss or percentile).
func handleGetCVEsAboveThreshold(c *cli.Context) error {
	thresholdStr := c.String("threshold")
	threshold, err := strconv.ParseFloat(thresholdStr, 64)
	if err != nil {
		return fmt.Errorf("invalid threshold value: %w", err)
	}
	field := c.String("field")
	repo := repository.NewAPIRepository("https://api.first.org/data/v1/epss")
	cves, err := repo.GetCVEsAboveThreshold(threshold, field)
	if err != nil {
		return fmt.Errorf("failed to get CVEs above threshold: %w", err)
	}
	for _, cve := range cves {
		fmt.Printf("CVE ID: %s, EPSS Score: %f, Percentile: %f, Date: %s\n", cve.ID, cve.EPSSScore, cve.Percentile, cve.Date)
	}
	return nil
}

func main() {
	app := &cli.App{
		Name:  "epss",
		Usage: "EPSS CLI tool for CVE vulnerability scoring",
		Commands: []*cli.Command{
			{
				Name:  "score",
				Usage: "Get EPSS score for a CVE",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "cve",
						Usage:    "CVE ID (e.g., CVE-2020-23151)",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "date",
						Usage: "Date in YYYY-MM-DD format",
					},
				},
				Action: handleGetScore,
			},
			{
				Name:  "topn",
				Usage: "Get the top N CVEs",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "n",
						Usage:    "Number of top CVEs",
						Required: true,
					},
				},
				Action: handleTopNCVEs,
			},
			{
				Name: "highest",
				Usage: "Get the highest increases in EPSS score",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "days",
						Usage:    "Number of days to look back",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "limit",
						Usage:    "Number of highest increases to return",
						Required: true,
					},
				},
				Action: handleHighestIncreases,
			},
			{
				Name:  "date",
				Usage: "Get CVEs for a specific date",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "date",
						Usage:    "Date in YYYY-MM-DD format",
						Required: true,
					},
				},
				Action: handleGetCVEsForDate,
			},
			{
				Name:  "timeseries",
				Usage: "Get time series data for a CVE",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "cve",
						Usage:    "CVE ID",
						Required: true,
					},
				},
				Action: handleGetTimeSeries,
			},
			{
				Name:  "threshold",
				Usage: "Get CVEs above a specific threshold",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "threshold",
						Usage:    "Threshold value",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "field",
						Usage:    "Field to check (epss or percentile)",
						Required: true,
					},
				},
				Action: handleGetCVEsAboveThreshold,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
