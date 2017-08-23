#!/bin/bash

echo
filepath="/etc/pve/qemu-server/101.conf"
if [ -e $filepath ];then

     echo "$filepath exists, You can't remove the zvol."
     echo "Cancel."
     exit 1
fi


read -p "Warning! Are you sure to remove [101] at [pve01]? [y/n]: " response1
response=$response1

if [[ $response =~ ^(yes|y)$ ]]
then
    echo
    echo "remove [101] at [pve01]..."
    echo
    pvecm expected 1

    # to destroy zvol
    zfs destroy -r rpool/data/vm-101-disk-1 

    echo
else
    echo
    echo "Cancel."
    echo
fi





