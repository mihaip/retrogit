package githop

import (
	"sort"
	"time"

	"github.com/google/go-github/github"
)

type RepoDigest struct {
	Repo    *github.Repository
	Commits []github.RepositoryCommit
}

// sort.Interface implementation for sorting RepoDigests.
type ByRepoFullName []*RepoDigest

func (a ByRepoFullName) Len() int           { return len(a) }
func (a ByRepoFullName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByRepoFullName) Less(i, j int) bool { return *a[i].Repo.FullName < *a[j].Repo.FullName }

type Digest struct {
	User        *github.User
	StartTime   time.Time
	EndTime     time.Time
	RepoDigests []*RepoDigest
}

func (digest *Digest) Fetch(repos []github.Repository, githubClient *github.Client) error {
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
					Since:  digest.StartTime,
					Until:  digest.EndTime,
				})
			if err != nil {
				ch <- &RepoDigestResponse{nil, err}
			} else {
				ch <- &RepoDigestResponse{&RepoDigest{&repo, commits}, nil}
			}
		}(repo)
	}
	for i := 0; i < len(repos); i++ {
		select {
		case r := <-ch:
			if r.err != nil {
				return r.err
			}
			digest.RepoDigests = append(digest.RepoDigests, r.repoDigest)
		}
	}
	sort.Sort(ByRepoFullName(digest.RepoDigests))
	return nil
}
