package ports

import (
	"github.com/joshbarros/golang-epsstool-api/internal/domain/models"
)

type EPSSService interface {
    GetCVEScore(cveID string, date string) (*models.CVE, error)
    GetTopNCVEs(n int) ([]models.CVE, error)
    GetHighestIncreases(days int, limit int) ([]models.ScoreChange, error)
}
