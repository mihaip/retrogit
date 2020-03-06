#!/bin/sh

# With the Go 1.11 runtime, if we're not using modules, all source (including
# the app itself) must live under GOPATH. Copy it there before deploying.
DEST="$GOPATH/src/retrogit"
rm -rf $DEST
cp -r app $DEST
cd $DEST
gcloud app deploy --project retro-git app.yaml
