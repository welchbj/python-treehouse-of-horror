#!/usr/bin/env bash

PUBLIC_LISTEN_PORT=${1:-12345}

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker.io

sudo service docker start
sudo docker build -t no-parens-jail .
sudo docker run -ti -p ${PUBLIC_LISTEN_PORT}:4444 no-parens-jail
