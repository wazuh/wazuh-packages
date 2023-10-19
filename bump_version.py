"""
This script is used to bump the version of the Wazuh packages repository.
    Copyright (C) 2015-2020, Wazuh Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
"""
import argparse
import datetime
import glob
import re
from packaging.version import Version

FORMAT_STRING="%m-%d-%Y"

arg_parser=argparse.ArgumentParser()
arg_parser.add_argument('-v', '--version', action='store', dest='version',
                        help='Version to bump to', required=True)
arg_parser.add_argument('-r', '--revision', action='store', dest='revision',
                        help='Revision to bump to. Default: 1', default=1)
arg_parser.add_argument('-d', '--date', action='store', dest='date',
                        help='Date to bump to. Format: m-d-Y. Default: today',
                        default=datetime.date.today().strftime(FORMAT_STRING))
args=arg_parser.parse_args()

date=datetime.datetime.strptime(args.date, FORMAT_STRING)
version=Version(args.version)

## Find files to bump .spec, changelog, pkginfo, .pkgproj, test-*.sh,
## installVariables.sh, CHANGELOG.md
spec_files=glob.glob('**/*.spec', recursive=True)
changelog_files=glob.glob('**/changelog', recursive=True)
copyright_files=glob.glob('**/copyright', recursive=True)
pkginfo_files=glob.glob('**/pkginfo', recursive=True)
pkgproj_files=glob.glob('**/*.pkgproj', recursive=True)
test_files=glob.glob('**/test-*.sh', recursive=True)
install_variables_files=glob.glob('**/installVariables.sh', recursive=True)
changelog_md_files=glob.glob('**/CHANGELOG.md', recursive=True)
VERSION_files=glob.glob('**/VERSION', recursive=True)

## Bump version in .spec files
SPEC_FORMAT_STRING="%a %b %d %Y"
spec_date=date.strftime(SPEC_FORMAT_STRING)
for spec_file in spec_files:
    with open(spec_file, 'r', encoding="utf-8") as file:
        print('Bumping version in ' + spec_file)
        filedata=file.read()
        # Replace version and revision
        REGEX=r'Version:\s*(\d+\.\d+\.\d+)'
        filedata=re.sub(REGEX, f"Version:     {version}", filedata)
        REGEX=r'Revision:\s*(\d+)'
        filedata=re.sub(REGEX, 'Revision:     ' + str(args.revision),
                          filedata)
        # Add new version to changelog
        REGEX=r'%changelog'
        changelog_string=(f"* {spec_date} support <info@wazuh.com> - {version}"
            "\n- More info: https://documentation.wazuh.com/current/release-"
            f"notes/release-{version.major}-{version.minor}-"
            f"{version.micro}.html")
        filedata=re.sub(REGEX, '%changelog\n' + changelog_string, filedata)

    with open(spec_file, 'w', encoding="utf-8") as file:
        file.write(filedata)

## Bump version in deb changelog files
DEB_FORMAT_STRING="%a, %d %b %Y %H:%M:%S +0000"
deb_changelog_date=date.strftime(DEB_FORMAT_STRING)
for changelog_file in changelog_files:
    with open(changelog_file, 'r', encoding="utf-8") as file:
        print('Bumping version in ' + changelog_file)
        filedata=file.read()
        install_type=re.search(r'(wazuh-(agent|manager|indexer|dashboard))',
                               filedata).group(1)
        changelog_string=(f"{install_type} ({version}-RELEASE) stable; "
            "urgency=low\n\n  * More info: https://documentation.wazuh.com/"
            f"current/release-notes/release-{version.major}-{version.minor}-"
            f"{version.micro}.html\n\n -- "
            f"Wazuh, Inc <info@wazuh.com>  {deb_changelog_date}\n\n")
        # Add new version to changelog
        filedata=changelog_string + filedata

    with open(changelog_file, 'w', encoding="utf-8") as file:
        file.write(filedata)

## Bump version in deb copyrigth files

for copyrigth_file in copyright_files:
    with open(copyrigth_file, 'r', encoding="utf-8") as file:
        print('Bumping version in ' + copyrigth_file)
        filedata=file.read()
        # Replace version and revision
        REGEX=(r'Wazuh, Inc <info@wazuh.com> on '
                r'(\w+),\s(\d+)\s(\w+)\s(\d+)\s(\d+):(\d+):(\d+)\s\+(\d+)')
        filedata=re.sub(REGEX,
                    f"Wazuh, Inc <info@wazuh.com> on {deb_changelog_date}",
                    filedata)

    with open(copyrigth_file, 'w', encoding="utf-8") as file:
        file.write(filedata)

## Bump version in pkginfo files

PKGINFO_FORMAT_STRING="%d%b%Y"

for pkginfo_file in pkginfo_files:
    with open(pkginfo_file, 'r', encoding="utf-8") as file:
        print('Bumping version in ' + pkginfo_file)
        filedata=file.read()
        # Replace version and revision
        REGEX=r'VERSION=\"(\d+\.\d+\.\d+)\"'
        filedata=re.sub(REGEX, f'VERSION=\"{version}\"', filedata)
        REGEX=r'PSTAMP=(.*)'
        filedata=re.sub(REGEX,
                    f'PSTAMP=\"{date.strftime(PKGINFO_FORMAT_STRING)}\"',
                    filedata)

    with open(pkginfo_file, 'w', encoding="utf-8") as file:
        file.write(filedata)

## Bump version in .pkgproj files

for pkgproj_file in pkgproj_files:
    with open(pkgproj_file, 'r', encoding="utf-8") as file:
        print('Bumping version in ' + pkgproj_file)
        filedata=file.read()
        # Replace version and revision
        REGEX=r'<string>(\d+\.\d+\.\d+)-(\d+)</string>'
        filedata=re.sub(REGEX, f'<string>{version}-{args.revision}</string>',
                          filedata)
        REGEX=r'<string>wazuh-agent-(\d+\.\d+\.\d+)-(\d+)'
        filedata=re.sub(REGEX,
                    f'<string>wazuh-agent-{version}-{args.revision}',
                    filedata)

    with open(pkgproj_file, 'w', encoding="utf-8") as file:
        file.write(filedata)

## Bump version in test-*.sh files

for test_file in test_files:
    with open(test_file, 'r', encoding="utf-8") as file:
        print('Bumping version in ' + test_file)
        filedata=file.read()
        # Replace version and revision
        REGEX=r'wazuh-manager.x86_64\s+(\d+\.\d+\.\d+)-(\d+)'
        filedata=re.sub(REGEX,
                    f'wazuh-manager.x86_64 {version}-{args.revision}',
                    filedata)
        REGEX=r'wazuh_version=\"(\d+\.\d+\.\d+)\"'
        filedata=re.sub(REGEX, f'wazuh_version=\"{version}\"', filedata)

    with open(test_file, 'w', encoding="utf-8") as file:
        file.write(filedata)

## Bump version in installVariables.sh files

for install_variables_file in install_variables_files:
    with open(install_variables_file, 'r', encoding="utf-8") as file:
        print('Bumping version in ' + install_variables_file)
        filedata=file.read()
        # Replace version and revision
        REGEX=r'wazuh_major=\"(\d+\.\d+)\"'
        filedata=re.sub(REGEX,
                    f'wazuh_major=\"{version.major}.{version.minor}\"',
                    filedata)
        REGEX=r'wazuh_version=\"(\d+\.\d+\.\d+)\"'
        filedata=re.sub(REGEX, f'wazuh_version=\"{version}\"', filedata)

    with open(install_variables_file, 'w', encoding="utf-8") as file:
        file.write(filedata)

## Bump version in CHANGELOG.md files

for changelog_md_file in changelog_md_files:
    with open(changelog_md_file, 'r', encoding="utf-8") as file:
        print('Bumping version in ' + changelog_md_file)
        filedata=file.read()
        # Add new version to changelog
        REGEX=(r'All notable changes to this project '
               r'will be documented in this file.')
        changelog_string=(f"## [{version}]\n\n- https://github.com/wazuh/"
                          f"wazuh-packages/releases/tag/v{version}\n")
        filedata=re.sub(REGEX, REGEX + '\n' + changelog_string,
                          filedata)

    with open(changelog_md_file, 'w', encoding="utf-8") as file:
        file.write(filedata)

## Bump version in VERSION files

for VERSION_file in VERSION_files:
    with open(VERSION_file, 'r', encoding="utf-8") as file:
        print('Bumping version in ' + VERSION_file)
        filedata=file.read()
        # Replace version and revision
        REGEX=r'(\d+\.\d+\.\d+)'
        filedata=re.sub(REGEX, f'{version}', filedata)

    with open(VERSION_file, 'w', encoding="utf-8") as file:
        file.write(filedata)
