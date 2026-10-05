package githubpr

import (
	"encoding/json"
	"github.com/getjump/airbag/operation"
	"strconv"
)

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
	wantURL := "https://github.com/" + p.Repository + "/pull/" + strconv.Itoa(response.Number)
	valid := response.Number > 0 && response.URL == wantURL && response.Title == p.Title && response.Body == p.Body && response.Draft != nil && *response.Draft == p.Draft &&
		response.Head.SHA == p.HeadCommit && response.Head.Ref == p.Head && response.Base.Ref == p.Base &&
		response.Head.Repo.FullName == p.Repository && response.Base.Repo.FullName == p.Repository
	return response.URL, valid
}
