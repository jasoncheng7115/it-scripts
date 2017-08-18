echo
read -r -p "Warning! Are you sure to migrate [102]? [y/n]: " response
response=$(response,,)

if [[ $response =~ ^(yes|y)$ ]]
then
    echo
    echo "Migrate [102] From pve01 to pve02(me)..."
    echo
    pvecm expected 1
    mv /etc/pve/nodes/pve01/qemu-server/102.conf \
    /etc/pve/nodes/pve02/qemu-server/
    echo
else
    echo
    echo "Cancel."
    echo
fi