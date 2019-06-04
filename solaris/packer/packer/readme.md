# Use packer to generate vagrant boxes.

You need to download the official ISO and put it in the same folder than the JSON files.

## Download links

- [solaris 10](http://download.oracle.com/otn/solaris/10/sol-10-u11-ga-x86-dvd.iso)
- [solaris11_3](http://download.oracle.com/otn/solaris/11_3/sol-11_3-text-x86.iso)

(YOU MUST ACCEPT THE ORACLE LICENSE AGREEMENT [HERE](https://www.oracle.com/technetwork/server-storage/solaris10/downloads/index.html) BEFORE TRY TO DOWNLOAD)

## Configuration

There is a script called postinstall.sh that is applied to both, solaris10 and solaris11. In this file, all the Wazuh's build dependencies are installed, the `vagrant` user is added to sudoers and the ssh access for this user is configured too.

## Using packer
```
# solaris 10 (just virtualbox)
packer build -only=virtualbox-iso -on-error=ask solaris10.json 

# solaris 11_3 (just virtualbox)
packer build -only=virtualbox-iso -on-error=ask solaris11_3.json 
```
Base boxes will be created in the builds/virtualbox directory.

## Testing the boxes:

This command will store the Vagrant box locally so you cant do `vagrant up` with the name selected.
```
vagrant box add <name><box.box>
```

Requires
-------
- Vargrant (1.5.1)
- Packer (0.6.0)
- Solaris 11_3 text installer
- Solaris 10 Update 11 DVD image
