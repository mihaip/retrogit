package githop

import (
	"time"

	"github.com/google/go-github/github"
)

type Repos struct {
	AllRepos              []*Repo
	UserRepos             []*Repo
	OrgRepos              []*OrgRepos
	OldestFirstCommitTime time.Time
}

type Repo struct {
	*github.Repository
}

type OrgRepos struct {
	Org   *github.Organization
	Repos []*Repo
}

func getRepos(githubClient *github.Client, user *github.User) (*Repos, error) {
	// The username parameter must be left blank so that we can get all of the
	// repositories the user has access to, not just ones that they own.
	clientUserRepos, _, err := githubClient.Repositories.List("", nil)
	if err != nil {
		return nil, err
	}

	repos := &Repos{}
	repos.UserRepos = make([]*Repo, 0, len(clientUserRepos))
	allRepoCount := len(clientUserRepos)
	for i := range clientUserRepos {
		repos.UserRepos = append(repos.UserRepos, &Repo{&clientUserRepos[i]})
	}

	orgs, _, err := githubClient.Organizations.List("", nil)
	if err != nil {
		return nil, err
	}

	repos.OrgRepos = make([]*OrgRepos, 0, len(orgs))
	for i := range orgs {
		org := &orgs[i]
		clientOrgRepos, _, err := githubClient.Repositories.ListByOrg(*org.Login, nil)
		if err != nil {
			return nil, err
		}

		orgRepos := make([]*Repo, 0, len(clientOrgRepos))
		allRepoCount += len(clientOrgRepos)
		for j := range clientOrgRepos {
			orgRepos = append(orgRepos, &Repo{&clientOrgRepos[j]})
		}
		repos.OrgRepos = append(repos.OrgRepos, &OrgRepos{org, orgRepos})
	}

	repos.AllRepos = make([]*Repo, 0, allRepoCount)
	repos.AllRepos = append(repos.AllRepos, repos.UserRepos...)
	for _, org := range repos.OrgRepos {
		repos.AllRepos = append(repos.AllRepos, org.Repos...)
	}

	// TODO: better computation of the oldest first commit via the stats API
	repos.OldestFirstCommitTime = time.Now().UTC()
	for _, repo := range repos.AllRepos {
		repoTime := repo.CreatedAt.UTC()
		if repoTime.Before(repos.OldestFirstCommitTime) {
			repos.OldestFirstCommitTime = repoTime
		}
	}

	return repos, nil
}
