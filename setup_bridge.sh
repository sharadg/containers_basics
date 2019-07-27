#! /bin/bash

brctl addbr cni0
ip link set cni0 up
ip addr add 10.240.0.1/24 dev cni0
