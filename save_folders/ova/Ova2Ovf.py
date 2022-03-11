#!/usr/bin/env python
# Copyright (C) 2019, Wazuh Inc.
#
# Ova2Ovf.py        Helper script to convert VBox .ova export
#                   for import to VMWare ESXi
#
# Original author: eshizhan https://github.com/eshizhan
# Author: Neova Health
# forked from : https://gist.github.com/eshizhan/6650285
# Modified by Wazuh, Inc

import sys
import tarfile
import os
import hashlib
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--srcfile', help="Source VirtualBox Ova", type=str, dest='srcfile')
parser.add_argument('-d', '--destfile', help="Modified Ova", type=str, dest='destfile')
args = parser.parse_args()

if not args.srcfile or not args.destfile:
    print("Source Ova and Destination Ova are needed")
    exit

srcfile = args.srcfile
fileName, fileExtension = os.path.splitext(srcfile)
destfile = args.destfile

with tarfile.open(srcfile) as t:
    ovaFiles = t.getnames()
    t.extractall()


ovaF = ovaFiles[0]
ovaV = ovaFiles[1]


with open(ovaF) as fn:
    fp=fn.read()
    if hasattr(fp, 'decode'):
        fp = fp.decode('utf-8')

    fp = fp.replace('<OperatingSystemSection ovf:id="80">','<OperatingSystemSection ovf:id="101">')
    fp = fp.replace('<vssd:VirtualSystemType>virtualbox-2.2','<vssd:VirtualSystemType>vmx-7')
    fp = fp.replace('<rasd:Caption>sataController', '<rasd:Caption>scsiController')
    fp = fp.replace('<rasd:Description>SATA Controller','<rasd:Description>SCSI Controller')
    fp = fp.replace('<rasd:ElementName>sataController','<rasd:ElementName>scsiController')
    fp = fp.replace('<rasd:ResourceSubType>AHCI', '<rasd:ResourceSubType>lsilogic')
    fp = fp.replace('<rasd:ResourceType>20', '<rasd:ResourceType>6')

    end = fp.find('<rasd:Caption>sound')
    start = fp.rfind('<Item>', 0, end)
    fp = fp[:start] + '<Item ovf:required="false">' + fp[start+len('<Item>'):]


with open(ovaF, 'wb') as nfp:
    nfp.write(fp.encode('utf8'))

# Create new .ova
with tarfile.open(destfile, "w") as t:
    for name in ovaFiles:
        t.add(name)
