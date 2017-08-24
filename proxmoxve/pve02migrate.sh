#!/bin/bash

echo
filepath="/etc/pve/nodes/pve01/qemu-server/101.conf"
if [ -e $filepath ];then 
     echo
else
     echo "$filepath not exists, You can't migrate the [101]."
     echo "Cancel."
     exit 1
fi


echo
read -p "Warning! Are you sure migrate [101] From pve01 to pve02? [y/n]: " userinput
response=$userinput

if [[ $response =~ ^(yes|y)$ ]]
then
    echo
    echo "Migrate [101] From pve01 to pve02(me)..."
    echo
    pvecm expected 1
    sleep 2
    
    # copy vm config from pve01 to pve02, then you can start it.
    mv /etc/pve/nodes/pve01/qemu-server/101.conf \
    /etc/pve/nodes/pve02/qemu-server/
    sleep 2

    # del repl conf, u need setting again.    
    echo "Del Old Replication Conf..."
    rm /etc/pve/replication.cfg
    sleep 2

    # remove replicate temp snapshot.    
    echo "Destroy Temp Replicate Snapshot..."
    zfs destroy -f $(zfs list -t snapshot | grep vm-101 | awk '{print$ 1}')
    sleep 2

    echo
    read -r -p "Start [101] now ? [y/n]: " userinput
    response=$userinput
    if [[ $response =~ ^(yes|y)$ ]]
    then
        echo "Start [101]..."
        qm start 101
        sleep 2
    fi



else
    echo
    echo "Cancel."
    echo
fi