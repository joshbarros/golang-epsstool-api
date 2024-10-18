package models

import "time"

type CVE struct {
	ID         string
	EPSSScore  float64
	Percentile float64
	Date       string
}

type ScoreChange struct {
	CVE         string
	Date        time.Time
	ScoreChange float64
}
