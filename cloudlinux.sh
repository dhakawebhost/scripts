#!/bin/bash

# Installing CloudLinux
echo "Installing CloudLinux"
wget https://repo.cloudlinux.com/cloudlinux/sources/cln/cldeploy
cl_key=$(key | awk -F"." '{print $1}')
echo 'Enter CloudLinux key: '
read -r "cl_key"
sh cldeploy -k "$cl_key"
echo "CloudLinux installed. Setup needed things from WHM"

echo -en '\n'

echo "Rebooting the server"
sleep 3s
reboot -h


