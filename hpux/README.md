# HOWTO compile Wazuh Agent on HP-UX


## 1. Requirements:

First we need gcc, gmake, ginstall and many other gnu tools.
The best to get this software is using the gnu repository of http://hpux.connect.org.uk/

The maintainer made a tool called depothelper that you can get here:
http://hpux.connect.org.uk/hppd/hpux/Sysadmin/depothelper-2.10/

http://hpux.connect.org.uk/ftp/hpux/Sysadmin/depothelper-2.10/depothelper-2.10-hppa_32-11.31.depot.gz

Download depothelper and scp-it to your HP-UX machine

```
wget http://hpux.connect.org.uk/ftp/hpux/Sysadmin/depothelper-2.10/depothelper-2.10-hppa_32-11.31.depot.gz
gunzip depothelper-2.10-hppa_32-11.31.depot.gz
```

Install it (you must be root):
```
swinstall -s /path/to/qyqak/depothelper-2.10-hppa_32-11.31.depot \*
````

Install required packages
```
/usr/local/bin/depothelper curl
/usr/local/bin/depothelper unzip
/usr/local/bin/depothelper gcc
/usr/local/bin/depothelper make
/usr/local/bin/depothelper coreutils
/usr/local/bin/depothelper perl
```

## 2. Download and extract Wazuh

```
cd /tmp
/usr/local/bin/curl -k -L -O https://github.com/wazuh/wazuh/archive/3.2.zip
/usr/local/bin/unzip 3.2.zip
```

## 3. Compile & Install Wazuh

```
cd /tmp/wazuh-3.2
/usr/local/bin/gmake -C src TARGET=agent
sh install.sh
```

If you want a faster way, you can specify the flags

```
echo USER_LANGUAGE="en" > wazuh/etc/preloaded-vars.conf
echo USER_NO_STOP="y" >> wazuh/etc/preloaded-vars.conf
echo USER_INSTALL_TYPE="agent" >> wazuh/etc/preloaded-vars.conf
echo USER_DIR="/var/ossec" >> wazuh/etc/preloaded-vars.conf
echo USER_DELETE_DIR="y" >> wazuh/etc/preloaded-vars.conf
echo USER_CLEANINSTALL="y" >> wazuh/etc/preloaded-vars.conf
echo USER_BINARYINSTALL="y" >> wazuh/etc/preloaded-vars.conf
echo USER_AGENT_SERVER_IP="MANAGER_IP" >> wazuh/etc/preloaded-vars.conf
echo USER_ENABLE_SYSCHECK="y" >> wazuh/etc/preloaded-vars.conf
echo USER_ENABLE_ROOTCHECK="y" >> wazuh/etc/preloaded-vars.conf
echo USER_ENABLE_OPENSCAP="y" >> wazuh/etc/preloaded-vars.conf
echo USER_ENABLE_ACTIVE_RESPONSE="y" >> wazuh/etc/preloaded-vars.conf
echo USER_CA_STORE="/path/to/my_cert.pem" >> wazuh/etc/preloaded-vars.conf
```

## 4. Generate .tar file


```
rm /var/ossec/wodles/oscap/content/*.xml
tar -cvf /tmp/wazuh-agent-3.2.2-1-hpux-11v3-ia64.tar /var/ossec/ /etc/ossec-init.conf /sbin/init.d/wazuh-agent /sbin/rc2.d/S97wazuh-agent /sbin/rc3.d/S97wazuh-agent
```

## 5. [Optional] Uninstall the agent

```
/var/ossec/bin/ossec-control stop
rm -rf /var/ossec/
rm /etc/ossec-init.conf
rm /sbin/init.d/wazuh-agent
rm /sbin/rc2.d/S97wazuh-agent
rm /sbin/rc3.d/S97wazuh-agent
userdel ossec
groupdel ossec
```


## 6. [Optional] Useful packages

You can add optional packages (bash, vim, ...)

```
/usr/local/bin/depothelper bash
/usr/local/bin/depothelper vim
/usr/local/bin/depothelper gdb

alias vim=/usr/local/bin/vim
```
