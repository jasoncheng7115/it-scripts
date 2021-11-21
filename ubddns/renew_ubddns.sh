#!/bin/bash
#-------------------------------------------------------
#
# UBDDNS Automatic IP monitoring for changes and updates
#
# Script by : Jason Cheng
# Website : www.jason.tools / blog.jason.tools
# Version : 1.0
# Date : 2021/11/21
#
#-------------------------------------------------------

# The name of the DDNS domain name
DDNSNAME="yourdomain"
DDNSDOMAIN="ubddns.org"
DDNSID="youraccount"
DDNSPW="yourpassword"

# Test
#DDNSNAME="test"
#DDNSDOMAIN="jason.tools"
#DDNSID="test"
#DDNSPW="testpw"


# UBDDNS Server (IPv4 only)
DDNSSRV="ipv4.ubddns.org"
#DDNSSRV="ubddns.org"

# Logger App Name
LOGAPPNAME="RENEW_UBDDNS"


# -------------------------------------

# Get ip now
NOWIP=`curl -s "ifconfig.me"`

# Get DDNS ip
DDNSIP=`nslookup $DDNSNAME.$DDNSDOMAIN | grep Address: | tail -n 1 | cut -d ":" -f 2| sed s/[[:space:]]//g`

echo "NOW IP : $NOWIP"
echo "DDNS IP : $DDNSIP"


# check get ip is correct format
if [[ $NOWIP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
then

  if [ "$NOWIP" = "$DDNSIP" ]
  then

    echo "IP is same. ($NOWIP)"
    logger -p info -t $LOGAPPNAME "Current IP=$NOWIP"

  else

    echo "IP is not same, DDNS updating..."
    DDNSRESULT=`curl -s -k "https://$DDNSSRV/do_updateip.php?account=$DDNSID&pass=$DDNSPW&userdomain=$DDNSNAME&maindomain=$DDNSDOMAIN"`

    logger -p info -t $LOGAPPNAME "IP is not same, DDNS updating...($DDNSIP should be change to $NOWIP)"

    if [[ $DDNSRESULT =~ "request code is 0" ]]
    then
      echo "DDNS IP update successfully."
      logger -p info -t $LOGAPPNAME "DDNS IP update successfully."
    else
      echo "DDNS IP update failure."
      logger -p alert -t $LOGAPPNAME "DDNS IP update failure. ($DDNSRESULT)"
    fi

  fi

else

  echo "Can't get the correct ip from config.me."
  logger -p alert -t $LOGAPPNAME "Can't get the correct ip from config.me ($NOWIP)"

fi
