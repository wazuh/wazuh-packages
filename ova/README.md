Wazuh Virtual Machine
=====================

In this repository, you can find the necessary tools to build your own OVA file with all Wazuh components installed.

## Tools needed to build the OVA:

To build an OVA you need to install the following tools:
- `Virtual Box`: [installation guide](https://www.virtualbox.org/manual/UserManual.html#installation)
- `Vagrant`: [installation guide](https://www.vagrantup.com/docs/installation/)
- `Git`:  [installation guide](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).
- `Python`: [installation guide](https://www.python.org/download/releases/2.7/)


## Building OVA file:

To generate the ova file, you need to download this repository and use the `generate_ova.sh` script. This script will create a vagrant box and provision it to be ready to use wazuh, as specified on provision.sh, and then export it to an Ova file.

```shellsession
# ./generate_ova.sh -h

OPTIONS:
      -b, --build            [Required] Build the OVA and OVF.
      -v, --version          [Required] Version of wazuh to install on VM.
      -e, --elastic-version  [Required] Elastic version to download inside VM.
      -r, --repository       [Required] Status of the packages [stable/unstable]
      -c, --clean            [Optional] Clean the local machine.
      -h, --help             [  Util  ] Show this help.
```

To build an OVA with version 3.9.0 using elastic 6.6.2 and the stable repositories you can use:

`# ./generate_ova.sh -b -v 3.9.5 -e 7.3.0 -r stable`

   * **Stable:** The OVA uses released packages.
   * **Unstable:** The OVA uses unstable packages.

## More Packages

- [RPM](/rpms/README.md)
- [Debian](/debs/README.md)
- [macOS](/macos/README.md)
- [AIX](/aix/README.md)
- [KibanaApp](/wazuhapp/README.md)
- [SplunkApp](/splunkapp/README.md)
- [WPK](/wpk/README.md)
- [Solaris](/solaris/README.md)
- [HP-UX](/hpux/README.md)

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com)or join to our Slack channel by filling this [form](https://wazuh.com/community/join-us-on-slack/) to ask questions and participate in discussions.

## License and copyright

WAZUH Copyright (C) 2016-2019 Wazuh Inc.  (License GPLv2)
