#!/bin/sh
ifconfig mon0 down
rmmod np_mon
make clean
make
insmod ./np_mon.ko
ifconfig mon0 up
