#!/bin/bash

# Exit on any error
set -e

sudo /opt/google-cloud-sdk/bin/gcloud docker push us.gcr.io/${PROJECT_NAME}/portcullis
sudo chown -R ubuntu:ubuntu /home/ubuntu/.kube
kubectl patch deployment portcullis -p '{"spec":{"template":{"spec":{"containers":[{"name":"portcullis","image":"us.gcr.io/${PROJECT_NAME}/portcullis:'"$CIRCLE_SHA1"'"}]}}}}'