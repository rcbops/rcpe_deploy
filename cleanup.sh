#!/bin/bash

sudo virsh destroy pxeappliance
sudo virsh undefine pxeappliance
sudo qemu-nbd -d /dev/nbd0
