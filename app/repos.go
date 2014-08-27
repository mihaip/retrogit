package githop

import (
	"fmt"
	"time"

	"appengine"
	"appengine/datastore"
	"appengine/delay"

	"github.com/google/go-github/github"
)

const (
	VintageDateFormat = "January 2, 2006"
)

type RepoVintage struct {
	UserId  int       `datastore:",noindex"`
	RepoId  int       `datastore:",noindex"`
	Vintage time.Time `datastore:",noindex"`
}

func getVintageKey(c appengine.Context, userId int, repoId int) *datastore.Key {
	return datastore.NewKey(c, "RepoVintage", fmt.Sprintf("%d-%d", userId, repoId), 0, nil)
}

func computeVintage(c appengine.Context, userId int, userLogin string, repoOwnerLogin string, repoName string) error {
	account, err := getAccount(c, userId)
	if err != nil {
		c.Errorf("Could not load account %d: %s", userId, err.Error())
		return err
	}

	oauthTransport := githubOAuthTransport(c)
	oauthTransport.Token = &account.OAuthToken
	githubClient := github.NewClient(oauthTransport.Client())

	repo, _, err := githubClient.Repositories.Get(repoOwnerLogin, repoName)
	if err != nil {
		c.Errorf("Could not load repo %d %d: %s", repoOwnerLogin, repoName, err.Error())
		return err
	}

	beforeCreationTime := repo.CreatedAt.UTC().AddDate(0, 0, -1)
	commits, _, err := githubClient.Repositories.ListCommits(
		repoOwnerLogin,
		repoName,
		&github.CommitsListOptions{
			ListOptions: github.ListOptions{PerPage: 1},
			Author:      userLogin,
			Until:       beforeCreationTime,
		})

	if err != nil {
		c.Errorf("Could not load commits for repo %s: %s", *repo.FullName, err.Error())
		return err
	}

	if len(commits) > 0 {
		// TODO: compute vintage via the stats API
	} else {
		_, err = datastore.Put(c, getVintageKey(c, userId, *repo.ID), &RepoVintage{
			UserId:  userId,
			RepoId:  *repo.ID,
			Vintage: repo.CreatedAt.UTC(),
		})
		if err != nil {
			c.Errorf("Could save vintage for repo %s: %s", *repo.FullName, err.Error())
			return err
		}
	}

	return nil
}

var computeVintageFunc = delay.Func("computeVintage", computeVintage)

func fillVintages(c appengine.Context, user *github.User, repos []*Repo) error {
	keys := make([]*datastore.Key, len(repos))
	for i := range repos {
		keys[i] = getVintageKey(c, *user.ID, *repos[i].ID)
	}
	vintages := make([]*RepoVintage, len(repos))
	for i := range vintages {
		vintages[i] = new(RepoVintage)
	}
	err := datastore.GetMulti(c, keys, vintages)
	if err != nil {
		if errs, ok := err.(appengine.MultiError); ok {
			for i, err := range errs {
				if err == datastore.ErrNoSuchEntity {
					vintages[i] = nil
				} else if err != nil {
					c.Errorf("%d/%s vintage fetch error: %s", i, *repos[i].FullName, err.Error())
					return err
				}
			}
		} else {
			return err
		}
	}
	for i := range vintages {
		repo := repos[i]
		vintage := vintages[i]
		if vintage != nil {
			repo.Vintage = vintage.Vintage
			continue
		}
		computeVintageFunc.Call(c, *user.ID, *user.Login, *repo.Owner.Login, *repo.Name)
	}
	return nil
}

type Repos struct {
	AllRepos       []*Repo
	UserRepos      []*Repo
	OtherUserRepos []*UserRepos
	OrgRepos       []*OrgRepos
	OldestVintage  time.Time
}

type Repo struct {
	*github.Repository
	Vintage time.Time
}

func newRepo(githubRepo *github.Repository) *Repo {
	return &Repo{githubRepo, githubRepo.CreatedAt.UTC()}
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

func (repo *Repo) TypeAsClassName() string {
	if *repo.Fork {
		return "fork"
	}
	if *repo.Private {
		return "private"
	}
	return ""
}

func (repo *Repo) DisplayVintage() string {
	return repo.Vintage.Format(VintageDateFormat)
}

type UserRepos struct {
	User  *github.User
	Repos []*Repo
}

type OrgRepos struct {
	Org   *github.Organization
	Repos []*Repo
}

func getRepos(c appengine.Context, githubClient *github.Client, user *github.User) (*Repos, error) {
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
			repos.UserRepos = append(repos.UserRepos, newRepo(&clientUserRepos[i]))
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
			userRepos.Repos = append(userRepos.Repos, newRepo(&clientUserRepos[i]))
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
			orgRepos = append(orgRepos, newRepo(&clientOrgRepos[j]))
		}
		repos.OrgRepos = append(repos.OrgRepos, &OrgRepos{org, orgRepos})
	}

	repos.AllRepos = make([]*Repo, 0, allRepoCount)
	repos.AllRepos = append(repos.AllRepos, repos.UserRepos...)
	for _, userRepos := range repos.OtherUserRepos {
		repos.AllRepos = append(repos.AllRepos, userRepos.Repos...)
	}
	for _, org := range repos.OrgRepos {
		repos.AllRepos = append(repos.AllRepos, org.Repos...)
	}

	err = fillVintages(c, user, repos.AllRepos)
	if err != nil {
		return nil, err
	}

	repos.OldestVintage = time.Now().UTC()
	for _, repo := range repos.AllRepos {
		repoVintage := repo.Vintage
		if repoVintage.Before(repos.OldestVintage) {
			repos.OldestVintage = repoVintage
		}
	}

	return repos, nil
}
