#!/bin/bash
# bakpveconf.sh
hostname=$(hostname)
fn_date=$(date "+%Y%m%d.%H%M")
bak_targetpath=$1
/bin/tar -zcvf ${bak_targetpath}/pveconf_${hostname}_${fn_date}_.tar.gz /etc/pve
