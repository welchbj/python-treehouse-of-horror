#!/usr/bin/env bash

PUBLIC_LISTEN_PORT=${1:-12345}

service docker start
docker build -t no-parens-jail .
docker run -ti -p ${PUBLIC_LISTEN_PORT}:4444 no-parens-jail
