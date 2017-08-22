echo
read -r -p "Warning! Are you sure to migrate [102]? [y/n]: " response
response=$(response,,)

if [[ $response =~ ^(yes|y)$ ]]
then
    echo
    echo "Migrate [102] From pve01 to pve03(me)..."
    echo
    pvecm expected 1

    ## copy vm config from pve01 to pve03, then you can start it.
    mv /etc/pve/nodes/pve01/qemu-server/102.conf \
    /etc/pve/nodes/pve03/qemu-server/
    echo
else
    echo
    echo "Cancel."
    echo
fi