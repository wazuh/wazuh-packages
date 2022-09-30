Wazuh packages
==============

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

Wazuh is an Open Source Host-based Intrusion Detection System that performs log analysis, file integrity monitoring, policy monitoring, rootkit detection, real-time alerting, active response, vulnerability detector, etc.

In this repository, you can find the necessary tools to build a Wazuh package for Debian based OS, RPM based OS package, Arch based OS, macOS, RPM packages for IBM AIX, the OVA, and the apps for Kibana and Splunk:

- [AIX](/aix/README.md)
- [Arch](/arch/README.md)
- [Debian](/debs/README.md)
- [HP-UX](/hp-ux/README.md)
- [KibanaApp](/wazuhapp/README.md)
- [macOS](/macos/README.md)
- [OVA](/ova/README.md)
- [RPM](/rpms/README.md)
- [SplunkApp](/splunkapp/README.md)
- [Solaris](/solaris/README.md)
- [Windows](/windows/README.md)

## Branches

* `master` branch contains the latest code, be aware of possible bugs on this branch.
* `stable` branch on correspond to the last Wazuh stable version.

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com) or join to our Slack channel by filling this [form](https://wazuh.com/community/join-us-on-slack/) to ask questions and participate in discussions.

<div class="X7AGAf">
    <div class="ptW7te" jsname="yjbGtf" aria-labelledby="c2" role="region">
        <html-blob>
            <div><span style="font-size: 14px;">Hello YNWA</span></div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><span style="font-size: 14px;">To achieve this you must do the following (I will assume that you are using the latest version available: v4.2.1 and 7.10.2)</span></div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><span style="font-size: 14px;">The file to modify is (public/plugin.ts):&nbsp;</span></div>
            <div>
                <span style="font-size: 14px;">
                    -
                    <a
                        href="https://github.com/wazuh/wazuh-kibana-app/blob/v4.2.1-7.10.2/public/plugin.ts"
                        target="_blank"
                        rel="nofollow"
                        data-saferedirecturl="https://www.google.com/url?hl=tr&amp;q=https://github.com/wazuh/wazuh-kibana-app/blob/v4.2.1-7.10.2/public/plugin.ts&amp;source=gmail&amp;ust=1664622367712000&amp;usg=AOvVaw12tG6yBYqerXbpw_fVCjHU"
                    >
                        https://github.com/wazuh/wazuh-kibana-app/blob/v4.2.1-7.10.2/public/plugin.ts
                    </a>
                </span>
            </div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><span style="font-size: 14px;">Specifically the lines:&nbsp;</span></div>
            <div>
                <span style="font-size: 14px;">
                    -
                    <a
                        href="https://github.com/wazuh/wazuh-kibana-app/blob/v4.2.1-7.10.2/public/plugin.ts#L38"
                        target="_blank"
                        rel="nofollow"
                        data-saferedirecturl="https://www.google.com/url?hl=tr&amp;q=https://github.com/wazuh/wazuh-kibana-app/blob/v4.2.1-7.10.2/public/plugin.ts%23L38&amp;source=gmail&amp;ust=1664622367712000&amp;usg=AOvVaw1J-x3ZojLhppkL2VR2wNSw"
                    >
                        https://github.com/wazuh/wazuh-kibana-app/blob/v4.2.1-7.10.2/public/plugin.ts#L38
                    </a>
                    (plugin name/title)
                </span>
            </div>
            <div>
                <span style="font-size: 14px;">
                    -
                    <a
                        href="https://github.com/wazuh/wazuh-kibana-app/blob/v4.2.1-7.10.2/public/plugin.ts#L65"
                        target="_blank"
                        rel="nofollow"
                        data-saferedirecturl="https://www.google.com/url?hl=tr&amp;q=https://github.com/wazuh/wazuh-kibana-app/blob/v4.2.1-7.10.2/public/plugin.ts%23L65&amp;source=gmail&amp;ust=1664622367712000&amp;usg=AOvVaw25cYsPNWnzp5eeTIuAHKMK"
                    >
                        https://github.com/wazuh/wazuh-kibana-app/blob/v4.2.1-7.10.2/public/plugin.ts#L65
                    </a>
                    (label)
                </span>
            </div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><span style="font-size: 14px;">Now:</span></div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><span style="font-size: 14px;">Download the wazuh-packages repository to generate a new custom app:</span></div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div>
                <span style="font-size: 14px;">
                    <b>
                        git clone
                        <a
                            href="https://github.com/wazuh/wazuh-packages"
                            target="_blank"
                            rel="nofollow"
                            data-saferedirecturl="https://www.google.com/url?hl=tr&amp;q=https://github.com/wazuh/wazuh-packages&amp;source=gmail&amp;ust=1664622367712000&amp;usg=AOvVaw27vlWNaPeRcFJDyQTzEHPm"
                        >
                            https://github.com/wazuh/wazuh-packages
                        </a>
                        &amp;&amp; cd wazuh-packages/wazuhapp &amp;&amp;
                    </b>
                </span>
            </div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div>
                <span style="font-size: 14px;">Add the following to the <b>Docker/build.sh</b> file in the <b>download_wazuh_app_sources()</b> method (depending on what you want to change):</span>
            </div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div>
                <span style="font-size: 14px;">To modify the title:&nbsp; &nbsp; &nbsp;<b>sed -i "s/title: 'Wazuh'/title: 'DefanSIEM'/g" ${kibana_dir}/plugins/wazuh/public/plugin.ts</b></span>
            </div>
            <div>
                <span style="font-size: 14px;">To modify the label:&nbsp; &nbsp;<b>sed -i "s/label: 'Wazuh'/label: 'DefanSIEM'/g" ${kibana_dir}/plugins/wazuh/public/plugin.ts</b></span>
            </div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><img alt="imagen.png" width="824px" height="166px" src="https://groups.google.com/group/wazuh/attach/2666ce5592ac6/imagen.png?part=0.4&amp;view=1" data-iml="4446.0999999996275" /><br /></div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><span style="font-size: 14px;">Generate the package, this will create a custom package in the output folder in the same directory where the script has been executed.</span></div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div>
                <span style="font-size: 14px;"><b>./generate_wazuh_app.sh -b v4.3.6-7.17.5</b></span>
            </div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div>
                <span style="font-size: 14px;">
                    At the end you will see a message like this, as this is created in a container, the package is transferred to your machine since a volume is used,&nbsp;you will see the generated package in an output folder
                </span>
            </div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><img alt="imagen2.png" width="890px" height="74px" src="https://groups.google.com/group/wazuh/attach/2666ce5592ac6/imagen2.png?part=0.1&amp;view=1" data-iml="3921.5" /><br /></div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div>
                <span style="font-size: 14px;"><img alt="imagen4.png" width="460px" height="290px" src="https://groups.google.com/group/wazuh/attach/2666ce5592ac6/imagen4.png?part=0.3&amp;view=1" data-iml="3902.699999999255" /><br /></span>
            </div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><span style="font-size: 14px;">Now we have to stop the Kibana service</span></div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div>
                <span style="font-size: 14px;"><b>systemctl stop kibana.service</b></span>
            </div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><span style="font-size: 14px;">Uninstall the plugin</span></div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div>
                <span style="font-size: 14px;"><b>cd /usr/share/kibana</b></span>
            </div>
            <div>
                <span style="font-size: 14px;"><b>sudo -u kibana bin/kibana-plugin remove wazuh</b></span>
            </div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><span style="font-size: 14px;">Install the custom plugin (assuming you have copy/move the package to /usr/share/kibana), where wazuh_kibana-4.2.1_7.10.2.zip is the generated package</span></div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div>
                <span style="font-size: 14px;"><b>cd /usr/share/kibana</b></span>
            </div>
            <div>
                <span style="font-size: 14px;"><b>sudo -u kibana bin/kibana-plugin install file:///usr/share/kibana/wazuh_kibana-4.2.1_7.10.2.zip</b></span>
            </div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><span style="font-size: 14px;">Clear your browser cache (depends on your browser), n</span>ow you should be able to see the changes:</div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><img alt="imagen3.png" width="364px" height="337px" src="https://groups.google.com/group/wazuh/attach/2666ce5592ac6/imagen3.png?part=0.2&amp;view=1" data-iml="4230.5" /><br /></div>
            <div>
                <span style="font-size: 14px;"><br /></span>
            </div>
            <div><span style="font-size: 14px;">The generation of the package is documented in this link:</span><br /></div>
            <div>
                <span style="font-size: 14px;">
                    -
                    <a
                        href="https://documentation.wazuh.com/current/development/packaging/generate-wazuh-kibana-app.html"
                        target="_blank"
                        rel="nofollow"
                        data-saferedirecturl="https://www.google.com/url?hl=tr&amp;q=https://documentation.wazuh.com/current/development/packaging/generate-wazuh-kibana-app.html&amp;source=gmail&amp;ust=1664622367712000&amp;usg=AOvVaw0O3eR_oq0d2QQlgrblCM9t"
                    >
                        https://documentation.wazuh.com/current/development/packaging/generate-wazuh-kibana-app.html
                    </a>
                </span>
            </div>
            <div><br /></div>
            <div><span style="font-size: 14px;">Another way to build the package is to follow this documentation, modifying the file that I mentioned at the beginning:&nbsp;</span></div>
            <div>
                <span style="font-size: 14px;">
                    -
                    <a
                        href="https://github.com/wazuh/wazuh-kibana-app/wiki/Develop-new-features"
                        target="_blank"
                        rel="nofollow"
                        data-saferedirecturl="https://www.google.com/url?hl=tr&amp;q=https://github.com/wazuh/wazuh-kibana-app/wiki/Develop-new-features&amp;source=gmail&amp;ust=1664622367712000&amp;usg=AOvVaw1XLiceEdlmE4SE4EppFX3H"
                    >
                        https://github.com/wazuh/wazuh-kibana-app/wiki/Develop-new-features
                    </a>
                </span>
            </div>
            <div>
                <span style="font-size: 14px;">
                    -
                    <a
                        href="https://github.com/wazuh/wazuh-kibana-app/wiki/Build-Wazuh-app-package"
                        target="_blank"
                        rel="nofollow"
                        data-saferedirecturl="https://www.google.com/url?hl=tr&amp;q=https://github.com/wazuh/wazuh-kibana-app/wiki/Build-Wazuh-app-package&amp;source=gmail&amp;ust=1664622367712000&amp;usg=AOvVaw1-TrktBY93pKKL0eFOgEdF"
                    >
                        https://github.com/wazuh/wazuh-kibana-app/wiki/Build-Wazuh-app-package
                    </a>
                </span>
            </div>
            <div><br /></div>
            <div>Regards, Raúl.</div>
        </html-blob>
    </div>
</div>
