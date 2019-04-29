wazuh-osx-installer
===================

OS X installer for Wazuh agent version 2.0

Unattended installation can be done running: 

```
sudo installer -pkg wazuh-agent.pkg -target /
```

OSSEC agent will be installed to:

```
/Library/Ossec
/Library/LaunchDaemons/
/Library/StartupItems/
```

Default agent configuration
---------------------------
```
<!--
  Wazuh - Agent - Default configuration for darwin .
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh
-->

<ossec_config>

   <client>
    <server-ip></server-ip>
    <config-profile>darwin</config-profile>
    <protocol>udp</protocol>
  </client>

  <syscheck>
    <!-- Frequency that syscheck is executed - default to every 22 hours -->
    <frequency>79200</frequency>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/cups/certs</ignore>
  </syscheck>

  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/Library/Ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/system.log</location>
  </localfile>


  <!-- Active response -->
  <active-response>
    <disabled>yes</disabled>
  </active-response>

</ossec_config>
```
