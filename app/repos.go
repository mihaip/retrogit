package main

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/appengine/v2"
	"google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/delay"
	"google.golang.org/appengine/v2/log"
	"google.golang.org/appengine/v2/taskqueue"

	"github.com/google/go-github/github"
)

const (
	VintageDateFormat = "January 2, 2006"
	VintageChunkSize  = 1000
)

type RepoVintage struct {
	UserId  int64     `datastore:",noindex"`
	RepoId  int64     `datastore:",noindex"`
	Vintage time.Time `datastore:",noindex"`
}

func getVintageKey(c context.Context, userId int64, repoId int64) *datastore.Key {
	return datastore.NewKey(c, "RepoVintage", fmt.Sprintf("%d-%d", userId, repoId), 0, nil)
}

var computeVintageFunc *delay.Function

func computeVintage(c context.Context, userId int64, userLogin string, repoId int64, repoOwnerLogin string, repoName string) error {
	account, err := getAccount(c, userId)
	if err != nil {
		log.Errorf(c, "Could not load account %d: %s. Presumed deleted, aborting computing vintage for %s/%s", userId, err.Error(), repoOwnerLogin, repoName)
		return nil
	}

	githubClient := githubOAuthClient(c, account.OAuthToken)

	repo, response, err := githubClient.Repositories.Get(c, repoOwnerLogin, repoName)
	if response.StatusCode == 403 || response.StatusCode == 404 {
		log.Warningf(c, "Got a %d when trying to look up %s/%s (%d)", response.StatusCode, repoOwnerLogin, repoName, repoId)
		_, err = datastore.Put(c, getVintageKey(c, userId, repoId), &RepoVintage{
			UserId:  userId,
			RepoId:  repoId,
			Vintage: time.Unix(0, 0),
		})
		return err
	} else if err != nil {
		log.Errorf(c, "Could not load repo %s/%s (%d): %s", repoOwnerLogin, repoName, repoId, err.Error())
		return err
	}

	// Cheap check to see if there are commits before the creation time.
	vintage := repo.CreatedAt.UTC()
	beforeCreationTime := repo.CreatedAt.UTC().AddDate(0, 0, -1)
	commits, response, err := githubClient.Repositories.ListCommits(
		c,
		repoOwnerLogin,
		repoName,
		&github.CommitsListOptions{
			ListOptions: github.ListOptions{PerPage: 1},
			Author:      userLogin,
			Until:       beforeCreationTime,
		})
	if response != nil && response.StatusCode == 409 {
		// GitHub returns with a 409 when a repository is empty.
		commits = make([]*github.RepositoryCommit, 0)
	} else if response != nil && response.StatusCode >= 500 {
		// Avoid retries if GitHub can't load commits (this happens for repos
		// like AOSiP-Devices/kernel_xiaomi_laurel_sprout, presumably because
		// they have too many commits).
		log.Warningf(c, "Could not load commits for repo %s (%d), not retrying: %s", *repo.FullName, repoId, err.Error())
		commits = make([]*github.RepositoryCommit, 0)
	} else if err != nil {
		log.Errorf(c, "Could not load commits for repo %s (%d), will retry: %s", *repo.FullName, repoId, err.Error())
		return err
	}

	// If there are, then we use the contributor stats API to figure out when
	// the user's first commit in the repository was.
	if len(commits) > 0 {
		stats, response, err := githubClient.Repositories.ListContributorsStats(c, repoOwnerLogin, repoName)
		if response.StatusCode == 202 {
			log.Infof(c, "Stats were not available for %s, will try again later", *repo.FullName)
			task, err := computeVintageFunc.Task(userId, userLogin, repoId, repoOwnerLogin, repoName)
			if err != nil {
				log.Errorf(c, "Could create delayed task for %s: %s", *repo.FullName, err.Error())
				return err
			}
			task.Delay = time.Second * 10
			taskqueue.Add(c, task, "")
			return nil
		}
		if err != nil {
			log.Errorf(c, "Could not load stats for repo %s: %s", *repo.FullName, err.Error())
			return err
		}
		for _, stat := range stats {
			if *stat.Author.ID == userId {
				for i := range stat.Weeks {
					weekTimestamp := stat.Weeks[i].Week.UTC()
					if weekTimestamp.Before(vintage) {
						vintage = weekTimestamp
					}
				}
				break
			}
		}
	}

	_, err = datastore.Put(c, getVintageKey(c, userId, repoId), &RepoVintage{
		UserId:  userId,
		RepoId:  repoId,
		Vintage: vintage,
	})
	if err != nil {
		log.Errorf(c, "Could save vintage for repo %s: %s", *repo.FullName, err.Error())
		return err
	}

	return nil
}

func init() {
	computeVintageFunc = delay.Func("computeVintage", computeVintage)
}

func fillVintages(c context.Context, user *github.User, repos []*Repo) error {
	if len(repos) > VintageChunkSize {
		for chunkStart := 0; chunkStart < len(repos); chunkStart += VintageChunkSize {
			chunkEnd := chunkStart + VintageChunkSize
			if chunkEnd > len(repos) {
				chunkEnd = len(repos)
			}
			err := fillVintages(c, user, repos[chunkStart:chunkEnd])
			if err != nil {
				return err
			}
		}
		return nil
	}
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
					log.Errorf(c, "%d/%s vintage fetch error: %s", i, *repos[i].FullName, err.Error())
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
			if vintage.Vintage.Unix() != 0 {
				repo.Vintage = vintage.Vintage
			}
			continue
		}
		computeVintageFunc.Call(c, *user.ID, *user.Login, *repo.ID, *repo.Owner.Login, *repo.Name)
	}
	return nil
}

type Repos struct {
	AllRepos       []*Repo
	UserRepos      []*Repo
	OtherUserRepos []*UserRepos
	OldestVintage  time.Time
}

func (repos *Repos) Redact() {
	for _, repo := range repos.UserRepos {
		*repo.HTMLURL = "https://redacted"
		*repo.FullName = "redacted/redacted"
	}
	for _, otherUserRepos := range repos.OtherUserRepos {
		*otherUserRepos.User.Login = "redacted"
		*otherUserRepos.User.AvatarURL = "https://redacted"
		for _, repo := range otherUserRepos.Repos {
			*repo.HTMLURL = "https://redacted"
			*repo.FullName = "redacted/redacted"
		}
	}
}

type Repo struct {
	*github.Repository
	Vintage         time.Time
	IncludeInDigest bool
}

func newRepo(githubRepo *github.Repository, account *Account) *Repo {
	return &Repo{
		Repository:      githubRepo,
		Vintage:         githubRepo.CreatedAt.UTC(),
		IncludeInDigest: !account.IsRepoIdExcluded(*githubRepo.ID),
	}
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

func getRepos(c context.Context, githubClient *github.Client, account *Account, user *github.User) (*Repos, error) {
	clientUserRepos := make([]*github.Repository, 0)
	page := 1
	for {
		pageClientUserRepos, response, err := githubClient.Repositories.List(
			c,
			// The username parameter must be left blank so that we can get all
			// of the repositories the user has access to, not just ones that
			// they own.
			"",
			&github.RepositoryListOptions{
				ListOptions: github.ListOptions{
					Page:    page,
					PerPage: 100,
				},
			})
		if err != nil {
			return nil, err
		}
		clientUserRepos = append(clientUserRepos, pageClientUserRepos...)
		if response.NextPage == 0 {
			break
		}
		page = response.NextPage
	}

	repos := &Repos{}
	repos.UserRepos = make([]*Repo, 0, len(clientUserRepos))
	repos.OtherUserRepos = make([]*UserRepos, 0)
	for i := range clientUserRepos {
		ownerID := *clientUserRepos[i].Owner.ID
		if ownerID == *user.ID {
			repos.UserRepos = append(repos.UserRepos, newRepo(clientUserRepos[i], account))
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
			userRepos.Repos = append(userRepos.Repos, newRepo(clientUserRepos[i], account))
		}
	}

	repos.AllRepos = make([]*Repo, 0, len(clientUserRepos))
	repos.AllRepos = append(repos.AllRepos, repos.UserRepos...)
	for _, userRepos := range repos.OtherUserRepos {
		repos.AllRepos = append(repos.AllRepos, userRepos.Repos...)
	}

	err := fillVintages(c, user, repos.AllRepos)
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
