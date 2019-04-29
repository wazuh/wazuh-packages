#! /bin/bash
# By Spransy, Derek" <DSPRANS () emory ! edu> and Charlie Scott
# Modified by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

#####
# This checks for an error and exits with a custom message
# Returns zero on success
# $1 is the message
# $2 is the error code

DIR="/Library/Ossec"

if [ ! -d ${DIR} ]; then
    launchctl setenv WAZUH_PKG_UPGRADE false
else
    launchctl setenv WAZUH_PKG_UPGRADE true
fi

if [[ ! -f "/usr/bin/dscl" ]]
  then
  echo "Error: I couldn't find dscl, dying here";
  exit
fi

DSCL="/usr/bin/dscl";

function check_errm
{
   if  [[ ${?} != "0" ]]
      then
      echo "${1}";
      exit ${2};
      fi
}

# get unique id numbers (uid, gid) that are greater than 100
unset -v i new_uid new_gid idvar;
declare -i new_uid=0 new_gid=0 i=100 idvar=0;
while [[ $idvar -eq 0 ]]; do
   i=$[i+1]
   if [[ -z "$(/usr/bin/dscl . -search /Users uid ${i})" ]] && [[ -z "$(/usr/bin/dscl . -search /Groups gid ${i})" ]];
      then
      new_uid=$i
      new_gid=$i
      idvar=1
      #break
   fi
done

echo "UID available for ossec user is:";
echo ${new_uid}

# Verify that the uid and gid exist and match
if [[ $new_uid -eq 0 ]] || [[ $new_gid -eq 0 ]];
   then
   echo "Getting unique id numbers (uid, gid) failed!";
   exit 1;
fi
if [[ ${new_uid} != ${new_gid} ]]
   then
   echo "I failed to find matching free uid and gid!";
   exit 5;
fi

# Stops the agent before upgrading it
if [ -f /Library/Ossec/bin/ossec-control ]; then
    /Library/Ossec/bin/ossec-control stop
fi

# Creating the group
if [[ $(dscl . -read /Groups/ossec) ]]
   then
   echo "ossec group already exists.";
else
   sudo ${DSCL} localhost -create /Local/Default/Groups/ossec
   check_errm "Error creating group ossec" "67"
   sudo ${DSCL} localhost -createprop /Local/Default/Groups/ossec PrimaryGroupID ${new_gid}
   sudo ${DSCL} localhost -createprop /Local/Default/Groups/ossec RealName ossec
   sudo ${DSCL} localhost -createprop /Local/Default/Groups/ossec RecordName ossec
   sudo ${DSCL} localhost -createprop /Local/Default/Groups/ossec RecordType: dsRecTypeStandard:Groups
   sudo ${DSCL} localhost -createprop /Local/Default/Groups/ossec Password "*"
fi

# Creating the user
if [[ $(dscl . -read /Users/ossec) ]]
   then
   echo "ossec user already exists.";
else
   sudo ${DSCL} localhost -create /Local/Default/Users/ossec
   check_errm "Error creating user ossec" "77"
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec RecordName ossec
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec RealName ossec
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec UserShell /usr/bin/false
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec NFSHomeDirectory /var/ossec
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec UniqueID ${new_uid}
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec PrimaryGroupID ${new_gid}
   sudo ${DSCL} localhost -append /Local/Default/Groups/ossec GroupMembership ossec
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec Password "*"
fi

#Hide the fixed users
dscl . create /Users/ossec IsHidden 1

sudo tee /Library/LaunchDaemons/com.wazuh.agent.plist <<-'EOF'
<?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
 <plist version="1.0">
 <dict>
     <key>Label</key>
     <string>com.wazuh.agent</string>
     <key>ProgramArguments</key>
     <array>
         <string>/Library/StartupItems/WAZUH/launcher.sh</string>
     </array>
     <key>RunAtLoad</key>
     <true/>
 </dict>
 </plist>
EOF
chown root:wheel /Library/LaunchDaemons/com.wazuh.agent.plist
chmod u=rw-,go=r-- /Library/LaunchDaemons/com.wazuh.agent.plist

sudo mkdir /Library/StartupItems/WAZUH
chown root:wheel /Library/StartupItems/WAZUH

sudo tee /Library/StartupItems/WAZUH/WAZUH <<-'EOF'
#!/bin/sh
. /etc/rc.common
. /etc/ossec-init.conf
if [ "X${DIRECTORY}" = "X" ]; then
    DIRECTORY="/Library/Ossec"
fi

StartService ()
{
        ${DIRECTORY}/bin/ossec-control start
}
StopService ()
{
        ${DIRECTORY}/bin/ossec-control stop
}
RestartService ()
{
        ${DIRECTORY}/bin/ossec-control restart
}
RunService "$1"
EOF
chown root:wheel /Library/StartupItems/WAZUH/WAZUH
chmod u=rwx,go=r-x /Library/StartupItems/WAZUH/WAZUH

sudo tee /Library/StartupItems/WAZUH/StartupParameters.plist <<-'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://
www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Description</key>
       <string>WAZUH Security agent</string>
       <key>Messages</key>
       <dict>
               <key>start</key>
               <string>Starting Wazuh agent</string>
               <key>stop</key>
               <string>Stopping Wazuh agent</string>
       </dict>
       <key>Provides</key>
       <array>
               <string>WAZUH</string>
       </array>
       <key>Requires</key>
       <array>
               <string>IPFilter</string>
       </array>
</dict>
</plist>
EOF
chown root:wheel /Library/StartupItems/WAZUH/StartupParameters.plist
chmod u=rw-,go=r-- /Library/StartupItems/WAZUH/StartupParameters.plist

sudo tee /Library/StartupItems/WAZUH/launcher.sh <<-'EOF'
#!/bin/sh

. /etc/ossec-init.conf

if [ "X${DIRECTORY}" = "X" ]; then
    DIRECTORY="/Library/Ossec"
fi

capture_sigterm() {
    ${DIRECTORY}/bin/ossec-control stop
    exit $?
}

if ! ${DIRECTORY}/bin/ossec-control start; then
    ${DIRECTORY}/bin/ossec-control stop
fi

while : ; do
    trap capture_sigterm SIGTERM
    sleep 3
done
EOF

chown root:wheel /Library/StartupItems/WAZUH/launcher.sh
chmod u=rxw-,go=rx- /Library/StartupItems/WAZUH/launcher.sh
