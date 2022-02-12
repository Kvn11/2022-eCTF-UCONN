#!/bin/bash

# Lets make sure that enough arguments were passed:
if (( $# < 3 ))
then
    echo "[!] Not enough arguments were passed"
    echo "usage: CreateDeployment.sh <sysname> <oldest-allowed-version> <uart-port>"
    exit 1
fi

SYSNAME=$1
OLDEST_ALLOWED_VERSION=$2
PORT=$3

# Build the deployment
python3 tools/run_saffire.py build-system --emulated --sysname $SYSNAME --oldest-allowed-version $OLDEST_ALLOWED_VERSION

# Launch the bootloader
python3 tools/run_saffire.py load-device --emulated $SYSNAME
mkdir socks -p
python3 tools/run_saffire.py launch-bootloader --emulated --sysname $SYSNAME --sock-root socks/ --uart-sock 1337 