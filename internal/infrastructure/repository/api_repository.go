package repository

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/joshbarros/golang-epsstool-api/internal/domain/models"
	"github.com/joshbarros/golang-epsstool-api/internal/domain/ports"
)

// apiRepository implements the ports.EPSSRepository interface using the First.org EPSS API.
type apiRepository struct {
	baseURL string
}

// NewAPIRepository creates a new apiRepository instance.
func NewAPIRepository(baseURL string) ports.EPSSRepository {
	return &apiRepository{baseURL: baseURL}
}

// buildURL constructs the API URL with the given parameters.
func (r *apiRepository) buildURL(params map[string]string) (string, error) {
	base, err := url.Parse(r.baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	query := base.Query()
	for k, v := range params {
		query.Add(k, v)
	}
	base.RawQuery = query.Encode()
	return base.String(), nil
}

// fetchData fetches data from the specified API URL.
func (r *apiRepository) fetchData(url string) ([]byte, error) {
	log.Printf("Fetching data from: %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, url)
	}

	return io.ReadAll(resp.Body)
}

// GetCVEScore retrieves the EPSS score for a given CVE ID and optional date.
func (r *apiRepository) GetCVEScore(cveID string, date string) (*models.CVE, error) {
	params := map[string]string{"cve": cveID}
	if date != "" {
		params["date"] = date
	}
	url, err := r.buildURL(params)
	if err != nil {
		return nil, err
	}
	data, err := r.fetchData(url)
	if err != nil {
		return nil, err
	}

	var result interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	cveData, err := convertAPIResponseToCVEData(result)
	if err != nil {
		return nil, err
	}

	if len(cveData) == 0 {
		return nil, fmt.Errorf("no CVE found for ID: %s", cveID)
	}

	return &cveData[0], nil
}

// GetTopNCVEs retrieves the top N CVEs based on EPSS score.
func (r *apiRepository) GetTopNCVEs(n int) ([]models.CVE, error) {
	params := map[string]string{"order": "!epss", "limit": strconv.Itoa(n)}
	url, err := r.buildURL(params)
	if err != nil {
		return nil, err
	}
	data, err := r.fetchData(url)
	if err != nil {
		return nil, err
	}

	var result interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	cves, err := convertAPIResponseToCVEDataArray(result)
	if err != nil {
		return nil, err
	}
	return cves, nil
}

func (r *apiRepository) GetHighestIncreases(days int, limit int) ([]models.ScoreChange, error) {
    now := time.Now()
    startDate := now.AddDate(0, 0, -days)

    // Create a map to store the highest score change for each CVE
    scoreChangesMap := make(map[string]float64)

    // Loop through each day in the past X days and fetch the data
    for i := 0; i <= days; i++ {
        date := startDate.AddDate(0, 0, i).Format("2006-01-02")
        params := map[string]string{"date": date}
        url, err := r.buildURL(params)
        if err != nil {
            return nil, err
        }

        data, err := r.fetchData(url)
        if err != nil {
            return nil, err
        }

        var result map[string]interface{}
        err = json.Unmarshal(data, &result)
        if err != nil {
            return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
        }

        cveList, err := convertAPIResponseToCVEDataArray(result)
        if err != nil {
            return nil, err
        }

        // Iterate over the data and calculate the score changes
        for _, cve := range cveList {
            initialScore, exists := scoreChangesMap[cve.ID]
            if exists {
                // Calculate the score change and update only if the new score change is higher
                scoreChange := cve.EPSSScore - initialScore
                if scoreChange > scoreChangesMap[cve.ID] {
                    scoreChangesMap[cve.ID] = scoreChange
                }
            } else {
                // Initialize the score change with the current EPSS score
                scoreChangesMap[cve.ID] = cve.EPSSScore
            }
        }
    }

    // Convert the score changes map to a list of ScoreChange structs
    var scoreChanges []models.ScoreChange
    for cveID, scoreChange := range scoreChangesMap {
        scoreChanges = append(scoreChanges, models.ScoreChange{
            CVE:         cveID,
            Date:        now,  // Store the current date for the score change entry
            ScoreChange: scoreChange,
        })
    }

    // Sort by the highest score changes
    sort.Slice(scoreChanges, func(i, j int) bool {
        return scoreChanges[i].ScoreChange > scoreChanges[j].ScoreChange
    })

    // Limit the result to the top N CVEs
    if len(scoreChanges) > limit {
        scoreChanges = scoreChanges[:limit]
    }

    return scoreChanges, nil
}


// GetCVEsForDate retrieves CVEs for a specific date.
func (r *apiRepository) GetCVEsForDate(date string) ([]models.CVE, error) {
	params := map[string]string{"date": date}
	url, err := r.buildURL(params)
	if err != nil {
		return nil, err
	}
	data, err := r.fetchData(url)
	if err != nil {
		return nil, err
	}

	var result interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	cves, err := convertAPIResponseToCVEDataArray(result)
	if err != nil {
		return nil, err
	}
	return cves, nil
}

// GetTimeSeries retrieves time series data for a given CVE ID.
func (r *apiRepository) GetTimeSeries(cveID string) ([]models.CVE, error) {
	params := map[string]string{"cve": cveID, "scope": "time-series"}
	url, err := r.buildURL(params)
	if err != nil {
		return nil, err
	}
	data, err := r.fetchData(url)
	if err != nil {
		return nil, err
	}

	var result interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	cves, err := convertAPIResponseToCVEDataArray(result)
	if err != nil {
		return nil, err
	}
	return cves, nil
}

// GetCVEsAboveThreshold retrieves CVEs above a specified threshold for a given field (epss or percentile).
func (r *apiRepository) GetCVEsAboveThreshold(threshold float64, field string) ([]models.CVE, error) {
	params := map[string]string{field + "-gt": strconv.FormatFloat(threshold, 'f', 2, 64)}
	url, err := r.buildURL(params)
	if err != nil {
		return nil, err
	}
	data, err := r.fetchData(url)
	if err != nil {
		return nil, err
	}

	var result interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	cves, err := convertAPIResponseToCVEDataArray(result)
	if err != nil {
		return nil, err
	}
	return cves, nil
}

// convertAPIResponseToCVEData converts a JSON response to a slice of CVE structs.
func convertAPIResponseToCVEData(item interface{}) ([]models.CVE, error) {
	data, ok := item.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", item)
	}
	apiData, ok := data["data"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", data["data"])
	}
	cves := make([]models.CVE, len(apiData))
	for i, item := range apiData {
		cveData := item.(map[string]interface{})
		cve, err := convertSingleAPIResponseToCVE(cveData)
		if err != nil {
			return nil, err
		}
		cves[i] = *cve
	}
	return cves, nil
}

// convertSingleAPIResponseToCVE converts a single JSON object to a CVE struct.
func convertSingleAPIResponseToCVE(item map[string]interface{}) (*models.CVE, error) {
	cveID, ok := item["cve"].(string)
	if !ok {
		return nil, fmt.Errorf("missing cve field")
	}
	epssScore, ok := item["epss"].(string)
	if !ok {
		return nil, fmt.Errorf("missing epss field")
	}
	percentile, ok := item["percentile"].(string)
	if !ok {
		return nil, fmt.Errorf("missing percentile field")
	}
	date, ok := item["date"].(string)
	if !ok {
		return nil, fmt.Errorf("missing date field")
	}
	epssFloat, err := strconv.ParseFloat(epssScore, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse epss field: %w", err)
	}
	percentileFloat, err := strconv.ParseFloat(percentile, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse percentile field: %w", err)
	}
	return &models.CVE{
		ID:         cveID,
		EPSSScore:  epssFloat,
		Percentile: percentileFloat,
		Date:       date,
	}, nil
}

// convertAPIResponseToCVEDataArray converts a JSON response to a slice of CVE structs.  Handles both single object and array responses.
func convertAPIResponseToCVEDataArray(item interface{}) ([]models.CVE, error) { // Converts API response to an array of CVE structs.
	data, ok := item.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", item)
	}
	apiData, ok := data["data"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", data["data"])
	}
	cves := make([]models.CVE, len(apiData))
	for i, item := range apiData {
		cve, err := convertSingleAPIResponseToCVE(item.(map[string]interface{}))
		if err != nil {
			return nil, err
		}
		cves[i] = *cve
	}
	return cves, nil
}
