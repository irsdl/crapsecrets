#!/usr/bin/env zsh
docker build --no-cache -t crapsecrets-container .
docker run --rm -it crapsecrets-container
