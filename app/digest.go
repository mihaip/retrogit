package githop

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/github"
)

const (
	DisplayDateFormat        = "3:04pm"
	DisplayDateTooltipFormat = "Monday January 2 3:04pm"
)

type DigestCommit struct {
	DisplaySHA       string
	URL              string
	Title            string
	Message          string
	PushDate         time.Time
	CommitDate       time.Time
	RepositoryCommit *github.RepositoryCommit
}

func newDigestCommit(commit *github.RepositoryCommit, repo *github.Repository, location *time.Location) DigestCommit {
	messagePieces := strings.SplitN(*commit.Commit.Message, "\n", 2)
	title := messagePieces[0]
	message := ""
	if len(messagePieces) == 2 {
		message = messagePieces[1]
	}
	return DigestCommit{
		DisplaySHA:       (*commit.SHA)[:7],
		URL:              fmt.Sprintf("https://github.com/%s/commit/%s", *repo.FullName, *commit.SHA),
		Title:            title,
		Message:          message,
		PushDate:         commit.Commit.Committer.Date.In(location),
		CommitDate:       commit.Commit.Author.Date.In(location),
		RepositoryCommit: commit,
	}
}

func (commit DigestCommit) DisplayDate() string {
	// Prefer the date the comit was pushed, since that's what GitHub filters
	// and sorts by.
	return commit.PushDate.Format(DisplayDateFormat)
}

func (commit DigestCommit) DisplayDateTooltip() string {
	// But show the full details in a tooltip
	return fmt.Sprintf(
		"Pushed at %s\nCommited at %s",
		commit.PushDate.Format(DisplayDateTooltipFormat),
		commit.CommitDate.Format(DisplayDateTooltipFormat))
}

type RepoDigest struct {
	Repo    *github.Repository
	Commits []DigestCommit
}

// sort.Interface implementation for sorting RepoDigests.
type ByRepoFullName []*RepoDigest

func (a ByRepoFullName) Len() int           { return len(a) }
func (a ByRepoFullName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByRepoFullName) Less(i, j int) bool { return *a[i].Repo.FullName < *a[j].Repo.FullName }

type Digest struct {
	User             *github.User
	StartTime        time.Time
	EndTime          time.Time
	TimezoneLocation *time.Location
	RepoDigests      []*RepoDigest
}

func newDigest(githubClient *github.Client, account *Account) (*Digest, error) {
	user, _, err := githubClient.Users.Get("")
	if err != nil {
		return nil, err
	}

	// The username parameter must be left blank so that we can get all of the
	// repositories the user has access to, not just ones that they own.
	repos, _, err := githubClient.Repositories.List("", nil)
	if err != nil {
		return nil, err
	}

	orgs, _, err := githubClient.Organizations.List("", nil)
	if err != nil {
		return nil, err
	}
	for _, org := range orgs {
		orgRepos, _, err := githubClient.Repositories.ListByOrg(*org.Login, nil)
		if err != nil {
			return nil, err
		}
		newRepos := make([]github.Repository, len(repos)+len(orgRepos))
		copy(newRepos, repos)
		copy(newRepos[len(repos):], orgRepos)
		repos = newRepos
	}

	now := time.Now().In(account.TimezoneLocation)
	digestStartTime := time.Date(now.Year()-1, now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	digestEndTime := digestStartTime.AddDate(0, 0, 1)

	// Only look at repos that may have activity in the digest interval.
	var digestRepos []github.Repository
	for _, repo := range repos {
		if repo.CreatedAt.Before(digestEndTime) && repo.PushedAt != nil &&
			repo.PushedAt.After(digestStartTime) {
			digestRepos = append(digestRepos, repo)
		}
	}
	repos = digestRepos
	digest := &Digest{
		User:             user,
		RepoDigests:      make([]*RepoDigest, 0, len(repos)),
		StartTime:        digestStartTime,
		EndTime:          digestEndTime,
		TimezoneLocation: account.TimezoneLocation,
	}
	err = digest.fetch(repos, githubClient)
	return digest, err
}

func (digest *Digest) fetch(repos []github.Repository, githubClient *github.Client) error {
	type RepoDigestResponse struct {
		repoDigest *RepoDigest
		err        error
	}
	ch := make(chan *RepoDigestResponse)
	for _, repo := range repos {
		go func(repo github.Repository) {
			commits, _, err := githubClient.Repositories.ListCommits(
				*repo.Owner.Login,
				*repo.Name,
				&github.CommitsListOptions{
					Author: *digest.User.Login,
					Since:  digest.StartTime.UTC(),
					Until:  digest.EndTime.UTC(),
				})
			if err != nil {
				ch <- &RepoDigestResponse{nil, err}
			} else {
				digestCommits := make([]DigestCommit, 0, len(commits))
				for i, _ := range commits {
					digestCommits = append(digestCommits, newDigestCommit(&commits[i], &repo, digest.TimezoneLocation))
				}
				ch <- &RepoDigestResponse{&RepoDigest{&repo, digestCommits}, nil}
			}
		}(repo)
	}
	for i := 0; i < len(repos); i++ {
		select {
		case r := <-ch:
			if r.err != nil {
				return r.err
			}
			if len(r.repoDigest.Commits) > 0 {
				digest.RepoDigests = append(digest.RepoDigests, r.repoDigest)
			}
		}
	}
	sort.Sort(ByRepoFullName(digest.RepoDigests))
	return nil
}

func (digest *Digest) DisplayDate() string {
	return digest.StartTime.Format("January 2, 2006 was a Monday")
}
