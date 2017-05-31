#!/bin/bash

docker stop webhook-diamondip
docker rm webhook-diamondip

docker build -t webhook-diamondip \
    --build-arg http_proxy=$(http_proxy) \
    --build-arg https_proxy=$(https_proxy) \
    .

docker run -p 5000:5000 -tid  \
    -v `pwd`/logs:/var/log \
    --name webhook-diamondip \
    webhook-diamondip
