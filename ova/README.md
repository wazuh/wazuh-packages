Wazuh generate OVA
====

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/) [![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh) [![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com) [![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

Wazuh is an Open Source Host-based Intrusion Detection System that performs log analysis, file integrity monitoring, policy monitoring, rootkit detection, real-time alerting, active response, vulnerability detector, etc.


In this repository, you can find the necessary tools to build your own OVA file with all Wazuh componets installed.

## Tools needed to build the OVA:
+ Virtual Box and Vagrant are needed to create a Centos 7 virtual machine and install on it all the components with the `provision.sh` script.

+ Python installed.


## Building OVA file:

Run the `generate_ova.sh` script to generate the OVA file. Those are the parameters: 

```shellsesion

# ./generate_ova.sh -h

  OPTIONS:
      -b,--build            [Required] Build the OVA and OVF.
      -v,--version          [Required] Version of wazuh to install on VM.
      -e,--elastic-version  [Required] Elastic version to download inside VM.
      -r,--repository       [Required] Status of the packages [stable/unstable]
      -c,--clean            [Optional] Clean the local machine.
      -h,--help             [  Util  ] Show this help.

```

  
 To build an OVA with the desired package:

      #./generate_ova.sh -b -v 3.9.0 -e 6.6.2 -r [stable/unstable]
    
   * **Stable:** The OVA uses released packages.
   * **Unstable:** The OVA uses unstable packages.

## More Packages

- [RPM](/rpms/README.md)
- [Debian](/debs/README.md)
- [MacOS](/macos/README.md)
- [AIX](/aix/README.md)
- [KibanaApp](/wazuhapp/README.md)
- [SplunkApp](/splunkapp/README.md)

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com) to ask questions and participate in discussions.

## License and copyright

WAZUH Copyright (C) 2016-2019 Wazuh Inc.  (License GPLv2)
