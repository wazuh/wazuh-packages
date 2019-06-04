# SOLARIS 10&11 TOOLS

## Packer: JSON & scripts

Use these JSON files and scripts to build new Vagrant boxes with [packer](https://www.packer.io/) 

You can also download the Vagrant boxes from our repo.

```
# Solaris 10

https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/utils/vagrant/solaris/10/solaris10.box

# Solaris 11

https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/utils/vagrant/solaris/11/i386/solaris11.3.box

```

or put that in a Vagrantfile:

```
Vagrant.configure("2") do |config|
  config.vm.box = "wazuh/solaris10U11.box"
  config.vm.box_url = "https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/utils/vagrant/solaris/11/i386/solaris11.3.box"
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


# solaris 11

vagrant box add solaris11wazuh solaris11.3.box
mkdir solaris11 && cd solaris11
vagrant init solaris11wazuh
vagrant up
vagrant ssh

```
based on [this work](https://github.com/BigAl/solaris-packer).


