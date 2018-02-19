Wazuh
=====

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://goo.gl/forms/M2AoZC4b2R9A9Zy12)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

Wazuh is an Open Source Host-based Intrusion Detection System that performs log analysis, file integrity checking, policy monitoring, rootkit detection, real-time alerting and active response.

These are the files used to create Wazuh debs and rpm packages, the ones in the Wazuh repository. You can find these packages at:

[Wazuh](https://wazuh.com) or visiting our [documentation](https://documentation.wazuh.com)

There are three different packages that can be built with these files:

* wazuh-manager: Package that includes the server.
* wazuh-agent: Package that includes just the agent.
* wazuh-api: Package that includes [RESTful API](https://documentation.wazuh.com/current/user-manual/api/index.html)


References about rpms:

https://techarena51.com/index.php/build-rpm-without-breaking-head/
https://wiki.centos.org/HowTos/SetupRpmBuildEnvironment
http://www.thegeekstuff.com/2015/02/rpm-build-package-example/

http://blog.celingest.com/en/2014/09/17/create-your-own-yum-rpm-repository-using-amazon-s3


References about debs:

http://santi-bassett.blogspot.ca/2014/07/setting-up-apt-repository-with-reprepro.html
https://debian-handbook.info/browse/stable/sect.building-first-package.html
http://www.hackgnar.com/2016/01/simple-deb-package-creation.html


Please don't hesitate to contribute (preferably via pull requests) to improve these packages.
