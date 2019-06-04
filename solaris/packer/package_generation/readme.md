Jenkins uses that folder for the Solaris package generation. There are two Vagrantfiles which accepts an argument for provisioning that specifies the version of the package needed to be generated. Also, there are two scripts for the provision of the machine inside the src folder (which will be a shared folder).


In order to manually generate packages using this tools you have to:

- Create a directory for the building process, for example `mkdir building && cd building`
- Create a `src` directory inside it. `mkdir src`
- Clone wazuh installers and put solaris11 or solaris10 (or both) inside src:
```
git clone git@github.com:wazuh/wazuh-installers.git
mv wazuh-installers/solaris/solaris1* src 
rm -rf wazuh-installers/ 
```
- **FOR SOLARIS 11:** clone wazuh-jenkins and copy the desired template file to the src file:

```
git clone https://github.com/wazuh/wazuh-jenkins
cp wazuh-jenkins/quality/tests/generic/common_files/check_files/agent/template_agent_vX.Y.Z.json src
```

- Bring up a virtual machine with vagrant using the following parameters: `vagrant --branch-tag=v3.9.0-rc7 up solaris10 solaris11`
