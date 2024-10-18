package repository_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/joshbarros/golang-epsstool-api/internal/infrastructure/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockClient struct {
	mock.Mock
}

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestGetCVEScore(t *testing.T) {
	t.Run("Success - Returns CVE Score", func(t *testing.T) {
		mockResponse := `{"data":[{"cve":"CVE-2023-0001","epss":"0.00044","percentile":"0.13","date":"2024-10-18"}]}`
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, mockResponse)
		}))
		defer mockServer.Close()

		repo := repository.NewAPIRepository(mockServer.URL)
		cve, err := repo.GetCVEScore("CVE-2023-0001", "2024-10-18")

		assert.NoError(t, err)
		assert.NotNil(t, cve)
		assert.Equal(t, "CVE-2023-0001", cve.ID)
		assert.Equal(t, 0.00044, cve.EPSSScore)
	})

	t.Run("Fail - Invalid CVE", func(t *testing.T) {
		mockResponse := `{"data":[]}`
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, mockResponse)
		}))
		defer mockServer.Close()

		repo := repository.NewAPIRepository(mockServer.URL)
		cve, err := repo.GetCVEScore("CVE-INVALID", "2024-10-18")

		assert.Error(t, err)
		assert.Nil(t, cve)
	})

	t.Run("Fail - API Error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}))
		defer mockServer.Close()

		repo := repository.NewAPIRepository(mockServer.URL)
		_, err := repo.GetCVEScore("CVE-2023-0001", "2024-10-18")

		assert.Error(t, err)
	})
}

func TestGetTopNCVEs(t *testing.T) {
	t.Run("Success - Returns Top CVEs", func(t *testing.T) {
		mockResponse := `{"data":[{"cve":"CVE-2023-0001","epss":"0.00044","percentile":"0.13","date":"2024-10-18"},{"cve":"CVE-2023-0002","epss":"0.00050","percentile":"0.15","date":"2024-10-18"}]}`
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, mockResponse)
		}))
		defer mockServer.Close()

		repo := repository.NewAPIRepository(mockServer.URL)
		cves, err := repo.GetTopNCVEs(2)

		assert.NoError(t, err)
		assert.Len(t, cves, 2)
		assert.Equal(t, "CVE-2023-0001", cves[0].ID)
	})

	t.Run("Fail - API Error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}))
		defer mockServer.Close()

		repo := repository.NewAPIRepository(mockServer.URL)
		_, err := repo.GetTopNCVEs(2)

		assert.Error(t, err)
	})
}

func TestGetHighestIncreases(t *testing.T) {
	t.Run("Success - Returns Highest Increases", func(t *testing.T) {
		// Mock response should include two CVEs with different score increases
		mockResponse := `{"data":[
			{"cve":"CVE-2023-0001","epss":"0.00040","percentile":"0.13","date":"2024-09-18"},
			{"cve":"CVE-2023-0002","epss":"0.00060","percentile":"0.15","date":"2024-09-18"}
		]}`
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, mockResponse)
		}))
		defer mockServer.Close()

		repo := repository.NewAPIRepository(mockServer.URL)

		// Test for 30 days lookback and limit to 2 CVEs
		scoreChanges, err := repo.GetHighestIncreases(30, 2)

		assert.NoError(t, err)
		assert.Len(t, scoreChanges, 2)

		// Assert based on score changes
		// CVE-2023-0002 has the highest increase in score
		assert.Equal(t, "CVE-2023-0002", scoreChanges[0].CVE)
		assert.Equal(t, 0.00060, scoreChanges[0].ScoreChange)

		// CVE-2023-0001 should come second
		assert.Equal(t, "CVE-2023-0001", scoreChanges[1].CVE)
		assert.Equal(t, 0.00040, scoreChanges[1].ScoreChange)
	})

	t.Run("Fail - API Error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}))
		defer mockServer.Close()

		repo := repository.NewAPIRepository(mockServer.URL)
		_, err := repo.GetHighestIncreases(30, 2)

		assert.Error(t, err)
	})
}

