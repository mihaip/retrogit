# RetroGit

Service that shows you your GitHub commits from previous years. Includes a mail digest to that you can see each day what you were up to in the past.

It's currently running at [https://www.retrogit.com/](https://www.retrogit.com/).

## Running Locally

1. Install Go 1.25 and a current [Google Cloud CLI](https://cloud.google.com/sdk/docs/install).

2. Install the App Engine local development server component:

```
gcloud components install app-engine-python
```

3. Authenticate if you need local access to Google Cloud services:

```
gcloud auth login
gcloud auth application-default login
```

4. Create `github-oauth.json` (you'll need to [register a new app](https://github.com/settings/applications/new) with GitHub) and `session.json` (with randomly-generated keys) files in the `config` directory, based on the sample files that are already there.

5. Run the local App Engine development server:

```
./dev.sh
```

The server can then be accessed at [http://localhost:8080/](http://localhost:8080/).

The local development server simulates App Engine bundled services such as
Datastore, Memcache, Mail, and Task Queues.

## Deploying to App Engine

```
./deploy.sh
```

`deploy.sh` deploys `app.yaml` and `queue.yaml`. Deploy `cron.yaml`
separately only when cron configuration changes.
