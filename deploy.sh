#!/bin/sh

set -e

cd app
gcloud app deploy --project retro-git app.yaml queue.yaml
