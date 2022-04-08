#!/bin/bash

./cleanup.sh

python3 tools/run_saffire.py build-system --emulated --sysname mike-test --oldest-allowed-version 1
python3 tools/run_saffire.py load-device --emulated --sysname mike-test
python3 tools/run_saffire.py launch-bootloader-gdb --emulated --sysname mike-test --sock-root ./socks/ --uart-sock 1337
gdb-multiarch mike-test-bootloader.elf.deleteme -ex 'target remote /home/team/Michael/2022-eCTF-UCONN/socks/gdb.sock'
python3 tools/run_saffire.py kill-system --emulated --sysname mike-test