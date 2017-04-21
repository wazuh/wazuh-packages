Wazuh
============

Wazuh is an Open Source Host-based Intrusion Detection System that performs log analysis, file integrity checking, policy monitoring, rootkit detection, real-time alerting and active response.

These are the files used to create Wazuh version 2.0 debs and rpms packages, the ones WAZUH repository. You can find these packages at:

[Wazuh](https://wazuh.com) or visiting our [documentation](http://documentation.wazuh.com)

There are three different packages that can be built with these files:

* wazuh-manager: Package that includes the server.
* wazuh-agent: Package that includes just the agent.
* wazuh-api: Package that includes [RESTful API](http://documentation.wazuh.com/en/latest/ossec_api.html)

Learn about create RPM's

https://techarena51.com/index.php/build-rpm-without-breaking-head/
https://wiki.centos.org/HowTos/SetupRpmBuildEnvironment
http://www.thegeekstuff.com/2015/02/rpm-build-package-example/


Learn about create your own YUM RPM using Amazon s3

http://blog.celingest.com/en/2014/09/17/create-your-own-yum-rpm-repository-using-amazon-s3

Learn about create Deb's packages

http://santi-bassett.blogspot.ca/2014/07/setting-up-apt-repository-with-reprepro.html
https://debian-handbook.info/browse/stable/sect.building-first-package.html
http://www.hackgnar.com/2016/01/simple-deb-package-creation.html

I hope it helps.

Please don't hesitate to contribute (preferably via pull requests) to improve these packages.
