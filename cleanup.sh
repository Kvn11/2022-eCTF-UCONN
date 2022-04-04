#!/bin/bash

echo y | docker image prune -a
echo y | docker image prune
docker container kill $(docker container ls -q)
echo y | docker container prune
docker volume rm $(docker volume ls -q)
rm ./socks/gdb.sock ./socks/restart.sock
