# SOLARIS 10&11 TOOLS

## Packer: JSON & scripts

Use these JSON files and scripts to build new Vagrant boxes with [packer](https://www.packer.io/) 

You can also download the Vagrant boxes from our repo.

## Solaris 10

["Solaris10 vagrant box"](https://packages-dev.wazuh.com/utils/vagrant/solaris/10/solaris10.box)

or put that in a Vagrantfile:

```
Vagrant.configure("2") do |config|
  config.vm.box = "wazuh/solaris10U11.box"
  config.vm.box_url = "packages-dev.wazuh.com/utils/vagrant/solaris/11/i386/solaris11.3.box"
end
```

## Testing generated boxes.

```
# solaris 10

vagrant box add solaris10wazuh solaris10.box
mkdir solaris10 && cd solaris10
vagrant init solaris10wazuh
vagrant up
vagrant ssh

```
based on [this work](https://github.com/BigAl/solaris-packer).

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
- Bring up a virtual machine with vagrant using the following parameters: `vagrant --branch-tag=v3.9.0-rc7 up solaris10`

