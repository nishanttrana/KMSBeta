package cicd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// JenkinsJobInfo represents a subset of the Jenkins job API response.
type JenkinsJobInfo struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Buildable  bool   `json:"buildable"`
	InQueue    bool   `json:"inQueue"`
	LastBuild  *JenkinsBuildRef `json:"lastBuild"`
	Color      string `json:"color"`
}

// JenkinsBuildRef represents a reference to a Jenkins build.
type JenkinsBuildRef struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
}

// ValidateJenkinsToken validates that a Jenkins job exists and is actively building
// by calling the Jenkins REST API with Basic auth.
// apiToken is in the format "username:api_token".
func ValidateJenkinsToken(apiToken, jenkinsURL, jobName string) error {
	if apiToken == "" {
		return fmt.Errorf("jenkins API token is required")
	}
	if jenkinsURL == "" {
		return fmt.Errorf("jenkins URL is required")
	}
	if jobName == "" {
		return fmt.Errorf("jenkins job name is required")
	}

	// Parse username:token
	parts := strings.SplitN(apiToken, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("jenkins API token must be in format 'username:api_token'")
	}
	username := parts[0]
	token := parts[1]

	// Normalize URL
	jenkinsURL = strings.TrimRight(jenkinsURL, "/")

	// Build the API URL, handling folder/nested jobs
	jobPath := buildJenkinsJobPath(jobName)
	apiURL := fmt.Sprintf("%s/%s/api/json", jenkinsURL, jobPath)

	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.SetBasicAuth(username, token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to contact Jenkins: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return fmt.Errorf("failed to read Jenkins response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// Parse job info
		var jobInfo JenkinsJobInfo
		if err := json.Unmarshal(body, &jobInfo); err != nil {
			return fmt.Errorf("failed to parse Jenkins job info: %w", err)
		}

		if !jobInfo.Buildable {
			return fmt.Errorf("jenkins job %q is not buildable (disabled)", jobName)
		}

		// Verify the job has an active or recent build
		isActive := jobInfo.InQueue || strings.HasSuffix(jobInfo.Color, "_anime")
		if !isActive && jobInfo.LastBuild == nil {
			return fmt.Errorf("jenkins job %q has no builds and is not currently building", jobName)
		}

		return nil

	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("jenkins authentication failed (status %d): invalid credentials", resp.StatusCode)

	case http.StatusNotFound:
		return fmt.Errorf("jenkins job %q not found", jobName)

	default:
		return fmt.Errorf("jenkins returned unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

// buildJenkinsJobPath converts a job name (possibly with folder separators) to a Jenkins API path.
// e.g., "folder/subfolder/job" becomes "job/folder/job/subfolder/job/job"
func buildJenkinsJobPath(jobName string) string {
	segments := strings.Split(jobName, "/")
	pathParts := make([]string, 0, len(segments)*2)
	for _, seg := range segments {
		pathParts = append(pathParts, "job", seg)
	}
	return strings.Join(pathParts, "/")
}
