package ports

import (
	"github.com/joshbarros/golang-epsstool-api/internal/domain/models"
)

type EPSSRepository interface {
	GetCVEScore(cveID string, date string) (*models.CVE, error)
	GetTopNCVEs(n int) ([]models.CVE, error)
	GetHighestIncreases(days int, limit int) ([]models.ScoreChange, error)
	GetCVEsForDate(date string) ([]models.CVE, error)
	GetTimeSeries(cveID string) ([]models.CVE, error)
	GetCVEsAboveThreshold(threshold float64, field string) ([]models.CVE, error)
}
