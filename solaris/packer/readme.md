Automated Wazuh Solaris10 packages using vagrant
==================

In this repository, you can find the necessary tools to build a Wazuh package for Solaris 10 using vagrant.

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
- `Virtual Box`: [installation guide](https://www.virtualbox.org/manual/UserManual.html#installation)
- `Vagrant`: [installation guide](https://www.vagrantup.com/docs/installation/)
- `Git`:  [installation guide](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git). 


## Building Solaris10 packages

To build a Solaris 10 package using vagrant, you need to download this repository copy the `Solaris10` directory into `packer/package_generation/vagrant/src` and run vagrant up. This will download a Solaris10 `vagrant box` and create a virtual machine where the `.pkg` package will be generated.

1. Download this repository and go to the rpm directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-packages
    $ cp -r wazuh-packages/solaris/solaris10 wazuh-packages/solaris/packer/package_generation/vagrant/src
    $ cd wazuh-packages/solaris/packer/package_generation/vagrant
    ```

2. Bring the machine up `vagrant [OPTION] ... up solaris10`:
    ```shellsession
      # vagrant -h up

       -- CUSTOM USE OF VAGRANT FOR THIS MACHINE --

        vagrant [OPTION] ... up solaris10

        vagrant [OPTION] ... ssh/provision/delete

        Example:

        vagrant --branch-tag=v3.7.2 --ram=1024 --cpus=4 up solaris10 

        -h, --help:
        Show help

        --branch-tag x, -b x:
        Generate package for branch/tag x

        --ram x
        Select the amount of ram asigned to the new machine.

        --cpus x
        Select the number of CPUs asigned to the new machine.

        -- DEFAULT USE OF VAGRANT (FOR ALL MACHINES) --

    Usage: vagrant [options] <command> [<args>]

        -v, --version                    Print the version and exit.
        -h, --help                       Print this help.

    Common commands:
        box             manages boxes: installation, removal, etc.
        cloud           manages everything related to Vagrant Cloud
        destroy         stops and deletes all traces of the vagrant machine
        global-status   outputs status Vagrant environments for this user
        halt            stops the vagrant machine
        help            shows the help for a subcommand
        init            initializes a new Vagrant environment by creating a Vagrantfile
        login
        package         packages a running vagrant environment into a box
        plugin          manages plugins: install, uninstall, update, etc.
        port            displays information about guest port mappings
        powershell      connects to machine via powershell remoting
        provision       provisions the vagrant machine
        push            deploys code in this environment to a configured destination
        rdp             connects to machine via RDP
        reload          restarts vagrant machine, loads new Vagrantfile configuration
        resume          resume a suspended vagrant machine
        scp             copies data into a box via SCP
        snapshot        manages snapshots: saving, restoring, etc.
        ssh             connects to machine via SSH
        ssh-config      outputs OpenSSH valid configuration to connect to the machine
        status          outputs status of the vagrant machine
        suspend         suspends the machine
        up              starts and provisions the vagrant environment
        upload          upload to machine via communicator
        validate        validates the Vagrantfile
        vbguest         plugin: vagrant-vbguest: install VirtualBox Guest Additions to the machine
        version         prints current and latest Vagrant version
        winrm           executes commands on a machine via WinRM
        winrm-config    outputs WinRM configuration to connect to the machine
    ```
    * To build a wazuh-agent package from branch v3.9.0 sources:
        `# vagrant --branch-tag=v3.9.0 up solaris10`.
    
3. After the virtual machine finishes generating the package you can find it in `src`.

4. Run `vagrant halt solaris10` to stop the machine or `vagrant destroy solaris10` to completely delete it.

In case you want to generate your own vagrant box for Solaris10 you can use the scripts within the packer directory:

To do this you will need the following dependencies in adition of the previously mentioned:
- `Packer`: [installation guide](https://www.packer.io/intro/getting-started/install.html)

1. Download the official Solaris10 ISO, to do this you, must first accept the [Oracle license agreement](https://www.oracle.com/technetwork/server-storage/solaris10/downloads/index.html) and then download the ISO:
- [Solaris 10](http://download.oracle.com/otn/solaris/10/sol-10-u11-ga-x86-dvd.iso)

2. Store the iso in packer/packer and use `packer build -only=virtualbox-iso -on-error=ask solaris10.json`, this will generate the Vagrant box.

3. Add the Vagrant box so you can use it locally, `vagrant add <name_box>.box`



## More Packages

- [RPM](/rpms/README.md)
- [Debian](/debs/README.md)
- [macOS](/macos/README.md)
- [AIX](/aix/README.md)
- [OVA](/ova/README.md)
- [KibanaApp](/wazuhapp/README.md)
- [SplunkApp](/splunkapp/README.md)
- [Solaris10](/solaris/solaris10/README.md)
 

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com)or join our Slack channel by filling this [form](https://wazuh.com/community/join-us-on-slack/) to ask questions and participate in discussions.

