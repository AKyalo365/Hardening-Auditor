#!/usr/bin/env bash

   perm=$(stat -c '%a' /etc/shadow)
   echo "Permissions on /etc/shadow: $perm"

   if [ "$perm" -le 640 ]; then
     echo "PASS"
   else
     echo "FAIL - password hashes may be readable by other users"
   fi
