#!/bin/bash

# nano /opt/zimbra/bin/zm-reindex-all.sh
# chmod +x /opt/zimbra/bin/zm-reindex-all.sh

# Get list of mail accounts and reindex each one
for i in `zmprov -l gaa -s yourdomain.com`
do

  echo -n "Reindexing $i"

  # Start reindexing
  zmprov rim $i start >/dev/null

  # Check if the rendix is still running for this account
  while [ `zmprov rim $i status|wc -l` != 1 ]
  do

    # Sleep for 2 seconds before checking status again
    echo -n . && sleep 2

  done

echo .
done