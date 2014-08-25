package githop

import (
	"time"

	"github.com/google/go-github/github"
)

type Repos struct {
	AllRepos              []*Repo
	UserRepos             []*Repo
	OtherUserRepos        []*UserRepos
	OrgRepos              []*OrgRepos
	OldestFirstCommitTime time.Time
}

type Repo struct {
	*github.Repository
}

type UserRepos struct {
	User  *github.User
	Repos []*Repo
}

type OrgRepos struct {
	Org   *github.Organization
	Repos []*Repo
}

func (repo *Repo) TypeAsOcticonName() string {
	if *repo.Fork {
		return "repo-forked"
	}
	if *repo.Private {
		return "lock"
	}
	return "repo"
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
	repos.OtherUserRepos = make([]*UserRepos, 0)
	allRepoCount := len(clientUserRepos)
	for i := range clientUserRepos {
		ownerID := *clientUserRepos[i].Owner.ID
		if ownerID == *user.ID {
			repos.UserRepos = append(repos.UserRepos, &Repo{&clientUserRepos[i]})
		} else {
			var userRepos *UserRepos
			for j := range repos.OtherUserRepos {
				if *repos.OtherUserRepos[j].User.ID == ownerID {
					userRepos = repos.OtherUserRepos[j]
					break
				}
			}
			if userRepos == nil {
				userRepos = &UserRepos{
					User:  clientUserRepos[i].Owner,
					Repos: make([]*Repo, 0),
				}
				repos.OtherUserRepos = append(repos.OtherUserRepos, userRepos)
			}
			userRepos.Repos = append(userRepos.Repos, &Repo{&clientUserRepos[i]})
		}
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
