#!/bin/sh

# With the Go 1.11 runtime, if we're not using modules, all source (including
# the app itself) must live under GOPATH. Copy it there before deploying.
cd app
gcloud app deploy --project retro-git app.yaml
