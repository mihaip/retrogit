package githop

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"appengine"

	"github.com/google/go-github/github"
)

const (
	CommitDisplayDateFormat        = "3:04pm"
	CommitDisplayDateTooltipFormat = "Monday January 2 3:04pm"
	DigestDisplayDateFormat        = "January 2, 2006 was a Monday"
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

func newDigestCommit(commit *github.RepositoryCommit, repo *Repo, location *time.Location) DigestCommit {
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
	// Prefer the date the commit was pushed, since that's what GitHub filters
	// and sorts by.
	return commit.PushDate.Format(CommitDisplayDateFormat)
}

func (commit DigestCommit) DisplayDateTooltip() string {
	// But show the full details in a tooltip
	return fmt.Sprintf(
		"Pushed at %s\nCommited at %s",
		commit.PushDate.Format(CommitDisplayDateTooltipFormat),
		commit.CommitDate.Format(CommitDisplayDateTooltipFormat))
}

type RepoDigest struct {
	Repo    *Repo
	Commits []DigestCommit
}

// sort.Interface implementation for sorting RepoDigests.
type ByRepoFullName []*RepoDigest

func (a ByRepoFullName) Len() int           { return len(a) }
func (a ByRepoFullName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByRepoFullName) Less(i, j int) bool { return *a[i].Repo.FullName < *a[j].Repo.FullName }

type IntervalDigest struct {
	yearDelta   int
	StartTime   time.Time
	EndTime     time.Time
	RepoDigests []*RepoDigest
	repos       []*Repo
}

func (digest *IntervalDigest) Empty() bool {
	for i := range digest.RepoDigests {
		if len(digest.RepoDigests[i].Commits) > 0 {
			return false
		}
	}
	return true
}

func (digest *IntervalDigest) Header() string {
	if digest.yearDelta == -1 {
		return "1 Year Ago"
	}
	return fmt.Sprintf("%d Years Ago", -digest.yearDelta)
}

func (digest *IntervalDigest) Description() string {
	commitCount := 0
	for i := range digest.RepoDigests {
		commitCount += len(digest.RepoDigests[i].Commits)
	}
	var formattedCommitCount string
	if commitCount == 0 {
		formattedCommitCount = "no commits"
	} else if commitCount == 1 {
		formattedCommitCount = "1 commit"
	} else {
		formattedCommitCount = fmt.Sprintf("%d commits", commitCount)
	}
	repoCount := len(digest.RepoDigests)
	var formattedRepoCount string
	if repoCount == 1 {
		formattedRepoCount = "1 repository"
	} else {
		formattedRepoCount = fmt.Sprintf("%d repositories", repoCount)
	}
	return fmt.Sprintf("%s. You had %s in %s that day.",
		digest.StartTime.Format(DigestDisplayDateFormat),
		formattedCommitCount,
		formattedRepoCount)
}

type Digest struct {
	User             *github.User
	TimezoneLocation *time.Location
	IntervalDigests  []*IntervalDigest
}

func newDigest(c appengine.Context, githubClient *github.Client, account *Account) (*Digest, error) {
	user, _, err := githubClient.Users.Get("")
	if err != nil {
		return nil, err
	}

	repos, err := getRepos(c, githubClient, user)
	if err != nil {
		return nil, err
	}

	oldestDigestTime := repos.OldestVintage.In(account.TimezoneLocation)
	intervalDigests := make([]*IntervalDigest, 0)
	now := time.Now().In(account.TimezoneLocation)
	for yearDelta := -1; ; yearDelta-- {
		digestStartTime := time.Date(now.Year()+yearDelta, now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		if digestStartTime.Before(oldestDigestTime) {
			break
		}
		digestEndTime := digestStartTime.AddDate(0, 0, 1)

		// Only look at repos that may have activity in the digest interval.
		var intervalRepos []*Repo
		for _, repo := range repos.AllRepos {
			if repo.Vintage.Before(digestEndTime) && repo.PushedAt != nil &&
				repo.PushedAt.After(digestStartTime) {
				intervalRepos = append(intervalRepos, repo)
			}
		}

		intervalDigests = append(intervalDigests, &IntervalDigest{
			yearDelta:   yearDelta,
			repos:       intervalRepos,
			RepoDigests: make([]*RepoDigest, 0, len(intervalRepos)),
			StartTime:   digestStartTime,
			EndTime:     digestEndTime,
		})
	}

	digest := &Digest{
		User:             user,
		TimezoneLocation: account.TimezoneLocation,
		IntervalDigests:  intervalDigests,
	}

	err = digest.fetch(githubClient)
	return digest, err
}

func (digest *Digest) fetch(githubClient *github.Client) error {
	type RepoDigestResponse struct {
		intervalDigest *IntervalDigest
		repoDigest     *RepoDigest
		err            error
	}
	fetchCount := 0
	ch := make(chan *RepoDigestResponse)
	for _, intervalDigest := range digest.IntervalDigests {
		for _, repo := range intervalDigest.repos {
			go func(intervalDigest *IntervalDigest, repo *Repo) {
				commits, _, err := githubClient.Repositories.ListCommits(
					*repo.Owner.Login,
					*repo.Name,
					&github.CommitsListOptions{
						Author: *digest.User.Login,
						Since:  intervalDigest.StartTime.UTC(),
						Until:  intervalDigest.EndTime.UTC(),
					})
				if err != nil {
					ch <- &RepoDigestResponse{nil, nil, err}
				} else {
					digestCommits := make([]DigestCommit, len(commits))
					for i := range commits {
						digestCommits[len(commits)-i-1] = newDigestCommit(&commits[i], repo, digest.TimezoneLocation)
					}
					ch <- &RepoDigestResponse{intervalDigest, &RepoDigest{repo, digestCommits}, nil}
				}
			}(intervalDigest, repo)
			fetchCount++
		}
	}
	for i := 0; i < fetchCount; i++ {
		select {
		case r := <-ch:
			if r.err != nil {
				return r.err
			}
			if len(r.repoDigest.Commits) > 0 {
				r.intervalDigest.RepoDigests = append(r.intervalDigest.RepoDigests, r.repoDigest)
			}
		}
	}
	nonEmptyIntervalDigests := make([]*IntervalDigest, 0, len(digest.IntervalDigests))
	for _, intervalDigest := range digest.IntervalDigests {
		if !intervalDigest.Empty() {
			nonEmptyIntervalDigests = append(nonEmptyIntervalDigests, intervalDigest)
			sort.Sort(ByRepoFullName(intervalDigest.RepoDigests))
		}
	}
	digest.IntervalDigests = nonEmptyIntervalDigests
	return nil
}

func (digest *Digest) Empty() bool {
	return len(digest.IntervalDigests) == 0
}
