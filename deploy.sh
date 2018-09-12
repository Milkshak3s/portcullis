#!/bin/bash

# Exit on any error
set -e

# Setup basic gcloud config
gcloud --quiet config set container/cluster $KUBE_CLUSTER
gcloud --quiet container clusters get-credentials $KUBE_CLUSTER

# Do the docker
docker build -t "portcullis:$CIRCLE_SHA1" .
docker tag "portcullis:$CIRCLE_SHA1" "us.gcr.io/${GOOGLE_PROJECT_ID}/portcullis:$CIRCLE_SHA1"
docker push "us.gcr.io/${GOOGLE_PROJECT_ID}/portcullis:$CIRCLE_SHA1"

# kube time
kubectl config set-context $(kubectl config current-context)
kubectl config view
kubectl config current-context
kubectl patch deployment portcullis-1 -p '{"spec":{"template":{"spec":{"containers":[{"name":"portcullis","image":"us.gcr.io/'"${GOOGLE_PROJECT_ID}"'/portcullis:'"$CIRCLE_SHA1"'"}]}}}}'