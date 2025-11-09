#!/bin/bash
# will need sudo chmod -R 1000:1000 data
docker run -it -d -p 2999:2999 -v ./data:/usr/src/app/data --name trusted-authority trusted-authority