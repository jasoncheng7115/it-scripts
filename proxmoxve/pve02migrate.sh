#!/bin/bash
echo
read -r -p "Warning! Are you sure to migrate [101]? [y/n]: " userinput
response=$userinput

if [[ $response =~ ^(yes|y)$ ]]
then
    echo
    echo "Migrate [101] From pve01 to pve02(me)..."
    echo
    pvecm expected 1
    
    ## copy vm config from pve01 to pve02, then you can start it.
    mv /etc/pve/nodes/pve01/qemu-server/101.conf \
    /etc/pve/nodes/pve02/qemu-server/

    # del repl conf, u need setting again.    
    rm /etc/pve/replication.cfg


    echo
    read -r -p "Start [101] now ? [y/n]: " userinput
    response=$userinput
    if [[ $response =~ ^(yes|y)$ ]]
    then
        echo "Start [101]..."
        qm start 101
    fi



else
    echo
    echo "Cancel."
    echo
fi