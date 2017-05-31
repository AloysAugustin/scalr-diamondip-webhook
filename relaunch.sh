#!/bin/bash

mkdir -p ./logs/supervisor/
mkdir -p ./logs/nginx/
mkdir -p ./logs/uwsgi/

docker stop webhook-diamondip
docker rm webhook-diamondip

docker build -t webhook-diamondip \
    --build-arg http_proxy=$http_proxy \
    --build-arg https_proxy=$https_proxy \
    .

docker run -p 5000:5000 -tid  \
    -v `pwd`/logs:/var/log \
    --name webhook-diamondip \
    webhook-diamondip
