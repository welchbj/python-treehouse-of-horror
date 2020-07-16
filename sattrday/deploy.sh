#!/usr/bin/env bash

PUBLIC_LISTEN_PORT=${1:-12345}

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker.io

service docker start
docker build -t sattrday .
docker run -ti -p ${PUBLIC_LISTEN_PORT}:4444 sattrday
