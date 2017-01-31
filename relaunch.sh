#!/bin/bash
docker stop webhook-diamondip
docker rm webhook-diamondip
docker build -t webhook-diamondip .
docker run -p 5000:5000 -tid --name webhook-diamondip webhook-diamondip
