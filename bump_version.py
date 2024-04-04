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
builder_files=glob.glob('**/unattended_installer/builder.sh', recursive=True)

#Format variables
SPEC_FORMAT_STRING="%a %b %d %Y"
spec_date=date.strftime(SPEC_FORMAT_STRING)
DEB_FORMAT_STRING="%a, %d %b %Y %H:%M:%S +0000"
deb_changelog_date=date.strftime(DEB_FORMAT_STRING)
PKGINFO_FORMAT_STRING="%d%b%Y"

#Regex-replacement dicts for each file
spec_files_dict = {
    r'Version:\s*(\d+\.\d+\.\d+)':f"Version:     {version}",    
    r'Revision:\s*(\d+)':'Revision:     ' + str(args.revision),
    r'%changelog':'%changelog\n' 
        + (f"* {spec_date} support <info@wazuh.com> - {version}"
        "\n- More info: https://documentation.wazuh.com/current/release-"
        f"notes/release-{version.major}-{version.minor}-"
        f"{version.micro}.html")}

copyright_files_dict = {
    (r'Wazuh, Inc <info@wazuh.com> on '
     r'(\w+),\s(\d+)\s(\w+)\s(\d+)\s(\d+):(\d+):(\d+)\s\+(\d+)'):
     f"Wazuh, Inc <info@wazuh.com> on {deb_changelog_date}"}

pkginfo_files_dict = {
    r'VERSION=\"(\d+\.\d+\.\d+)\"':f'VERSION=\"{version}\"',
    r'PSTAMP=(.*)':f'PSTAMP=\"{date.strftime(PKGINFO_FORMAT_STRING)}\"'}

pkgproj_files_dict = {
    r'<string>(\d+\.\d+\.\d+)-(\d+)</string>':
    f'<string>{version}-{args.revision}</string>',
    r'<string>wazuh-agent-(\d+\.\d+\.\d+)-(\d+)':
    f'<string>wazuh-agent-{version}-{args.revision}'}

test_files_dict = {
    r'wazuh-manager.x86_64\s+(\d+\.\d+\.\d+)-(\d+)':
    f'wazuh-manager.x86_64 {version}-{args.revision}',
    r'wazuh_version=\"(\d+\.\d+\.\d+)\"':
    f'wazuh_version=\"{version}\"'}

install_variables_files_dict = {
    r'wazuh_major=\"(\d+\.\d+)\"':
    f'wazuh_major=\"{version.major}.{version.minor}\"',
    r'wazuh_version=\"(\d+\.\d+\.\d+)\"':f'wazuh_version=\"{version}\"'}

changelog_md_files_dict = {
    (r'All notable changes to this project '
    r'will be documented in this file.'):
    (r'All notable changes to this project '
    r'will be documented in this file.') + '\n'  
    + (f"## [{version}]\n\n- https://github.com/wazuh/"
    f"wazuh-packages/releases/tag/v{version}\n")}

builder_files_dict = {
    r'source_branch=\"(\d+\.\d+\.\d+)\"': f'source_branch=\"{version}\"'}

VERSION_files_dict = {
    r'(\d+\.\d+\.\d+)': f'{version}'}


#Generic function to bump a file
def bump_file_list(file_list, regex_replacement):
    """Bumps a list of files matching the given regex and replacements

    Args:
        file_list(list):  path list for the selected files.
        regex_replacement(dict): specific dict for the file list where the key
        represent the regex to be matched and the value its replacement.
     """
    for bumping_file in file_list:
        with open(bumping_file, 'r', encoding="utf-8") as file:
            print('Bumping version in ' + bumping_file)
            filedata=file.read()
            for regex in regex_replacement:
                # Replace match
                filedata=re.sub(regex, regex_replacement[regex], filedata)

        with open(bumping_file, 'w', encoding="utf-8") as file:
            file.write(filedata)


## Bump version in deb changelog files
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


bump_file_list(spec_files,spec_files_dict)
bump_file_list(copyright_files,copyright_files_dict)
bump_file_list(pkginfo_files,pkginfo_files_dict)
bump_file_list(pkgproj_files,pkgproj_files_dict)
bump_file_list(test_files,test_files_dict)
bump_file_list(install_variables_files,install_variables_files_dict)
bump_file_list(changelog_md_files,changelog_md_files_dict)
bump_file_list(VERSION_files,VERSION_files_dict)
bump_file_list(builder_files,builder_files_dict)
