# GitHop

Service that shows you your GitHub commits from a year ago. Includes a mail digest to that you can see each day what you were up to in the past.

It's currently running at [https://git-hop.appspot.com/](https://git-hop.appspot.com/).

## Running Locally

First, [install the Go App Engine SDK](https://developers.google.com/appengine/downloads#Google_App_Engine_SDK_for_Go). Then run:

```
dev_appserver.py --enable_sendmail=yes app
```

The server can the be accessed at [http://localhost:8080/](http://localhost:8080/).

## Deploying to App Engine

```
goapp deploy -oauth app
```
