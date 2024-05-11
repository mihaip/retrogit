package main

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/appengine/v2/log"

	"github.com/google/go-github/github"
)

const (
	CommitDisplayDateFormat      = "3:04pm"
	CommitDisplayDateFullFormat  = "Monday January 2 3:04pm"
	DigestDisplayDateFormat      = "January 2, 2006"
	DigestDisplayShortDateFormat = "January 2"
	DigestDisplayDayOfWeekFormat = "Monday"
)

type DigestCommit struct {
	DisplaySHA string
	URL        string
	Title      string
	Message    string
	PushDate   time.Time
	CommitDate time.Time
}

func safeFormattedDate(date string) string {
	// Insert zero-width spaces every few characters so that Apple Data
	// Detectors and Gmail's calendar event dection don't pick up on these
	// dates.
	var buffer bytes.Buffer
	dateLength := len(date)
	for i := 0; i < dateLength; i += 2 {
		if i == dateLength-1 {
			buffer.WriteString(date[i : i+1])
		} else {
			buffer.WriteString(date[i : i+2])
			if date[i] != ' ' && date[i+1] != ' ' && i < dateLength-2 {
				buffer.WriteString("\u200b")
			}
		}
	}
	return buffer.String()
}

func newDigestCommit(commit *github.RepositoryCommit, repo *Repo, location *time.Location) DigestCommit {
	messagePieces := strings.SplitN(*commit.Commit.Message, "\n", 2)
	title := messagePieces[0]
	message := ""
	if len(messagePieces) == 2 {
		message = messagePieces[1]
	}
	return DigestCommit{
		DisplaySHA: (*commit.SHA)[:7],
		URL:        fmt.Sprintf("https://github.com/%s/commit/%s", *repo.FullName, *commit.SHA),
		Title:      title,
		Message:    message,
		PushDate:   commit.Commit.Committer.Date.In(location),
		CommitDate: commit.Commit.Author.Date.In(location),
	}
}

func (commit DigestCommit) DisplayDate() string {
	// Prefer the date the commit was pushed, since that's what GitHub filters
	// and sorts by.
	return safeFormattedDate(commit.PushDate.Format(CommitDisplayDateFormat))
}

func (commit DigestCommit) WeeklyDisplayDate() string {
	return safeFormattedDate(commit.PushDate.Format(CommitDisplayDateFullFormat))
}

func (commit DigestCommit) DisplayDateTooltip() string {
	// But show the full details in a tooltip
	return fmt.Sprintf(
		"Pushed at %s\nCommited at %s",
		commit.PushDate.Format(CommitDisplayDateFullFormat),
		commit.CommitDate.Format(CommitDisplayDateFullFormat))
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
	Weekly      bool
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

	if !digest.Weekly {
		return fmt.Sprintf("%s was a %s. You had %s in %s that day.",
			safeFormattedDate(digest.StartTime.Format(DigestDisplayDateFormat)),
			safeFormattedDate(digest.StartTime.Format(DigestDisplayDayOfWeekFormat)),
			formattedCommitCount,
			formattedRepoCount)
	}

	formattedEndTime := digest.EndTime.Format(DigestDisplayDateFormat)
	var formattedStartTime string
	if digest.StartTime.Year() == digest.EndTime.Year() {
		formattedStartTime = digest.StartTime.Format(DigestDisplayShortDateFormat)
	} else {
		formattedStartTime = digest.StartTime.Format(DigestDisplayDateFormat)
	}
	return fmt.Sprintf("You had %s in %s the week of %s to %s.",
		formattedCommitCount,
		formattedRepoCount,
		safeFormattedDate(formattedStartTime),
		safeFormattedDate(formattedEndTime))
}

type Digest struct {
	User             *github.User
	TimezoneLocation *time.Location
	IntervalDigests  []*IntervalDigest
	CommitCount      int
	RepoErrors       map[string]error
}

func newDigest(c context.Context, githubClient *github.Client, account *Account) (*Digest, error) {
	user, _, err := githubClient.Users.Get(c, "")
	if err != nil {
		return nil, err
	}

	repos, err := getRepos(c, githubClient, account, user)
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
		daysInDigest := 1
		if account.Frequency == "weekly" {
			daysInDigest = 7
		}
		digestEndTime := digestStartTime.AddDate(0, 0, daysInDigest).Add(-time.Second)

		// Only look at repos that may have activity in the digest interval.
		var intervalRepos []*Repo
		for _, repo := range repos.AllRepos {
			if repo.IncludeInDigest && repo.Vintage.Before(digestEndTime) && repo.PushedAt != nil &&
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
			Weekly:      account.Frequency == "weekly",
		})
	}

	digest := &Digest{
		User:             user,
		TimezoneLocation: account.TimezoneLocation,
		IntervalDigests:  intervalDigests,
		CommitCount:      0,
		RepoErrors:       make(map[string]error),
	}

	digest.fetch(c, githubClient)
	for repoFullName, err := range digest.RepoErrors {
		log.Errorf(c, "Error fetching %s: %s", repoFullName, err.Error())
	}
	return digest, nil
}

func (digest *Digest) fetch(c context.Context, githubClient *github.Client) {
	type RepoDigestResponse struct {
		intervalDigest *IntervalDigest
		repo           *Repo
		repoDigest     *RepoDigest
		err            error
	}
	fetchCount := 0
	ch := make(chan *RepoDigestResponse)
	for _, intervalDigest := range digest.IntervalDigests {
		for _, repo := range intervalDigest.repos {
			go func(intervalDigest *IntervalDigest, repo *Repo) {
				commits := make([]*github.RepositoryCommit, 0)
				page := 1
				for {
					pageCommits, response, err := githubClient.Repositories.ListCommits(
						c,
						*repo.Owner.Login,
						*repo.Name,
						&github.CommitsListOptions{
							ListOptions: github.ListOptions{
								Page:    page,
								PerPage: 100,
							},
							Author: *digest.User.Login,
							Since:  intervalDigest.StartTime.UTC(),
							Until:  intervalDigest.EndTime.UTC(),
						})
					if err != nil {
						ch <- &RepoDigestResponse{intervalDigest, repo, nil, err}
						return
					}
					commits = append(commits, pageCommits...)
					if response.NextPage == 0 {
						break
					}
					page = response.NextPage
				}
				digestCommits := make([]DigestCommit, len(commits))
				for i := range commits {
					digestCommits[len(commits)-i-1] = newDigestCommit(commits[i], repo, digest.TimezoneLocation)
				}
				ch <- &RepoDigestResponse{intervalDigest, repo, &RepoDigest{repo, digestCommits}, nil}
			}(intervalDigest, repo)
			fetchCount++
		}
	}
	for i := 0; i < fetchCount; i++ {
		select {
		case r := <-ch:
			if r.err != nil {
				digest.RepoErrors[*r.repo.FullName] = r.err
				continue
			}
			if len(r.repoDigest.Commits) > 0 {
				r.intervalDigest.RepoDigests = append(r.intervalDigest.RepoDigests, r.repoDigest)
				digest.CommitCount += len(r.repoDigest.Commits)
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
}

func (digest *Digest) Empty() bool {
	return len(digest.IntervalDigests) == 0
}

func (digest *Digest) Redact() {
	for _, intervalDigest := range digest.IntervalDigests {
		for _, repoDigest := range intervalDigest.RepoDigests {
			*repoDigest.Repo.HTMLURL = "https://redacted"
			*repoDigest.Repo.FullName = "redacted/redacted"
			for i := range repoDigest.Commits {
				commit := &repoDigest.Commits[i]
				commit.DisplaySHA = "0000000"
				commit.URL = "https://redacted"
				commit.Title = "Redacted"
				commit.Message = "Redacted redacted redacted"
			}
		}
	}
}
