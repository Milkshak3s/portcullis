#!/bin/bash

# Exit on any error
set -e

gcloud docker push us.gcr.io/${PROJECT_NAME}/portcullis
chown -R ubuntu:ubuntu /home/ubuntu/.kube
kubectl patch deployment portcullis -p '{"spec":{"template":{"spec":{"containers":[{"name":"portcullis","image":"us.gcr.io/${PROJECT_NAME}/portcullis:'"$CIRCLE_SHA1"'"}]}}}}'