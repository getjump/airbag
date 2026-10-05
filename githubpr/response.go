package githubpr

import (
	"encoding/json"
	"fmt"
	"github.com/getjump/airbag/operation"
	"strconv"
	"strings"
)

// HTTPError attests an actual GitHub error response, not a guessed status from
// a timeout or CLI diagnostic. Only observed 4xx responses establish refusal.
type HTTPError struct {
	StatusCode int
	Body       []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("GitHub refused the request (HTTP %d): %s", e.StatusCode, apiMessage(e.Body))
}

// apiMessage is the message of a GitHub error response, shortened.
func apiMessage(body []byte) string {
	var e struct {
		Message string `json:"message"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &e) != nil || e.Message == "" {
		return "no message"
	}
	m := e.Message
	for _, d := range e.Errors {
		if d.Message != "" {
			m += ": " + d.Message
		}
	}
	if len(m) > 300 {
		m = m[:300] + "…"
	}
	return m
}

// MatchResponse checks the returned PR against all frozen fields.
func MatchResponse(data []byte, p operation.PullRequest) (string, bool) {
	type repo struct {
		FullName string `json:"full_name"`
	}
	type branch struct {
		Ref  string `json:"ref"`
		SHA  string `json:"sha"`
		Repo repo   `json:"repo"`
	}
	var response struct {
		Number int    `json:"number"`
		URL    string `json:"html_url"`
		Title  string `json:"title"`
		Body   string `json:"body"`
		Draft  *bool  `json:"draft"`
		Head   branch `json:"head"`
		Base   branch `json:"base"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return "", false
	}
	// GitHub names owners and repositories case-insensitively and answers
	// with its own spelling of them; branches and the rest are exact.
	wantURL := "https://github.com/" + p.Repository + "/pull/" + strconv.Itoa(response.Number)
	valid := response.Number > 0 && strings.EqualFold(response.URL, wantURL) && response.Title == p.Title && response.Body == p.Body && response.Draft != nil && *response.Draft == p.Draft &&
		response.Head.SHA == p.HeadCommit && response.Head.Ref == p.Head && response.Base.Ref == p.Base &&
		strings.EqualFold(response.Head.Repo.FullName, p.Repository) && strings.EqualFold(response.Base.Repo.FullName, p.Repository)
	return response.URL, valid
}
