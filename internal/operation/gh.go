package operation

import (
	"fmt"
	"strings"
)

type PullRequestArguments struct {
	PullRequest PullRequest
	BodyFile    string
}

// ParsePullRequest accepts a deliberately narrow, noninteractive gh spelling.
// Unrecognized options on a create call are refused, not passed to a host CLI.
// Commit resolution and reading a body file are the capture handler's job.
func ParsePullRequest(argv []string) (PullRequestArguments, bool, error) {
	var out PullRequestArguments
	if len(argv) < 3 || argv[0] != "gh" {
		return out, false, nil
	}
	i := 1
	seen := map[string]bool{}
	read := func() (string, string, error) {
		a := argv[i]
		i++
		name, value, inline := strings.Cut(a, "=")
		switch name {
		case "-R":
			name = "--repo"
		case "-B":
			name = "--base"
		case "-H":
			name = "--head"
		case "-t":
			name = "--title"
		case "-b":
			name = "--body"
		case "-F":
			name = "--body-file"
		case "-d":
			name = "--draft"
		}
		switch name {
		case "--repo", "--base", "--head", "--title", "--body", "--body-file", "--draft":
		default:
			return "", "", fmt.Errorf("unsupported typed PR option %q", a)
		}
		if seen[name] {
			return "", "", fmt.Errorf("duplicate PR option %s", name)
		}
		seen[name] = true
		if name == "--draft" {
			if inline {
				return "", "", fmt.Errorf("--draft takes no value")
			}
			return name, "", nil
		}
		if !inline {
			if i >= len(argv) {
				return "", "", fmt.Errorf("missing value for %s", name)
			}
			value = argv[i]
			i++
		}
		return name, value, nil
	}
	// gh's repository option may precede the subcommands.
	for i < len(argv) && strings.HasPrefix(argv[i], "-") {
		name, value, err := read()
		if err != nil || name != "--repo" {
			matched := false
			for n := 1; n+1 < len(argv); n++ {
				if argv[n] == "pr" && argv[n+1] == "create" {
					matched = true
				}
			}
			if !matched {
				return out, false, nil
			}
			if err != nil {
				return out, true, err
			}
			return out, true, fmt.Errorf("only --repo may precede pr create")
		}
		out.PullRequest.Repository = value
	}
	if i+1 >= len(argv) || argv[i] != "pr" || argv[i+1] != "create" {
		return out, false, nil
	}
	i += 2
	for i < len(argv) {
		name, value, err := read()
		if err != nil {
			return out, true, err
		}
		switch name {
		case "--repo":
			out.PullRequest.Repository = value
		case "--base":
			out.PullRequest.Base = value
		case "--head":
			out.PullRequest.Head = value
		case "--title":
			out.PullRequest.Title = value
		case "--body":
			out.PullRequest.Body = value
		case "--body-file":
			out.BodyFile = value
		case "--draft":
			out.PullRequest.Draft = true
		}
	}
	if !seen["--repo"] || !seen["--base"] || !seen["--head"] || !seen["--title"] || seen["--body"] == seen["--body-file"] {
		return out, true, fmt.Errorf("typed PR creation requires explicit --repo, --base, --head, --title and exactly one of --body/--body-file")
	}
	if seen["--body-file"] && (out.BodyFile == "" || out.BodyFile == "-") {
		return out, true, fmt.Errorf("body-file must name a workspace file, not stdin")
	}
	return out, true, nil
}

type Preview struct {
	RequestDigest string    `json:"request_digest"`
	BodyDigest    string    `json:"body_digest"`
	Authority     Authority `json:"authority"`
	Request       Request   `json:"request"`
}

// Preview is a pure interpretation: no filesystem, credential or network use.
func (r Request) Preview() (Preview, error) {
	digest, err := r.Digest()
	if err != nil {
		return Preview{}, err
	}
	p := *r.PullRequest
	r.PullRequest = &p
	return Preview{RequestDigest: digest, BodyDigest: Hash([]byte(p.Body)), Authority: r.Authority(), Request: r}, nil
}
