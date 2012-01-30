#!/bin/bash

sudo virsh destroy pxeappliance
sudo virsh undefine pxeappliance
sudo qemu-nbd -d /dev/nbd0
sudo rm -rf /var/lock/shep_protection.lock
sudo rm -rf /opt/rcb/*
