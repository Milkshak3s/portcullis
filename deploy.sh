#!/bin/bash

# Exit on any error
set -e

docker build -t "portcullis:'"$CIRCLE_SHA1"'" .
docker tag "portcullis:'"$CIRCLE_SHA1"'" "us.gcr.io/'"${GOOGLE_PROJECT_ID}"'/portcullis:'"$CIRCLE_SHA1"'"
docker push "us.gcr.io/'"${GOOGLE_PROJECT_ID}"'/portcullis:'"$CIRCLE_SHA1"'"
chown -R ubuntu:ubuntu /home/ubuntu/.kube
kubectl patch deployment portcullis -p '{"spec":{"template":{"spec":{"containers":[{"name":"portcullis","image":"us.gcr.io/'"${GOOGLE_PROJECT_ID}"'/portcullis:'"$CIRCLE_SHA1"'"}]}}}}'