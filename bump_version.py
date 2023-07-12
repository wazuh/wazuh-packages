import argparse
import datetime
import glob, os
import re
from packaging.version import Version

format_string = "%m-%d-%Y"

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('-v', '--version', action='store', dest='version', help='Version to bump to', required=True)
arg_parser.add_argument('-r', '--revision', action='store', dest='revision', help='Revision to bump to. Default: 1', default=1)
arg_parser.add_argument('-d', '--date', action='store', dest='date', help='Date to bump to. Format: %m-%d-%Y. Default: today', default=datetime.date.today().strftime('%m-%d-%Y'))
args = arg_parser.parse_args()

date=datetime.datetime.strptime(args.date, format_string)
version=Version(args.version)

## Find files to bump .spec, changelog, pkginfo, .pkgproj, test-*.sh, installVariables.sh, CHANGELOG.md, README.md
spec_files = glob.glob('**/*.spec', recursive=True)
changelog_files = glob.glob('**/changelog', recursive=True)
pkginfo_files = glob.glob('**/pkginfo', recursive=True)
pkgproj_files = glob.glob('**/*.pkgproj', recursive=True)
test_files = glob.glob('**/test-*.sh', recursive=True)
install_variables_files = glob.glob('**/installVariables.sh', recursive=True)
changelog_md_files = glob.glob('**/CHANGELOG.md', recursive=True)
readme_md_files = glob.glob('**/README.md', recursive=True)

## Bump version in .spec files
spec_format_string = "%a %b %d %Y"
spec_date=date.strftime(spec_format_string)
for spec_file in spec_files:
    with open(spec_file, 'r') as file:
        print('Bumping version in ' + spec_file)
        filedata = file.read()
        # Replace version and revision
        regex = r'Version:\s*(\d+\.\d+\.\d+)'
        filedata = re.sub(regex, 'Version:     {}'.format(version), filedata)
        regex = r'Revision:\s*(\d+)'
        filedata = re.sub(regex, 'Revision:     ' + str(args.revision), filedata)
        # Add new version to changelog
        regex = r'%changelog'
        changelog_string="* {} support <info@wazuh.com> - {}\n- More info: https://documentation.wazuh.com/current/release-notes/release-{}-{}-{}.html".format(spec_date, version, version.major, version.minor, version.micro)
        filedata = re.sub(regex, '%changelog\n' + changelog_string, filedata)

    with open(spec_file, 'w') as file:
        file.write(filedata)

## Bump version in deb changelog files
deb_changelog_format_string = "%a, %d %b %Y %H:%M:%S +0000"
deb_changelog_date=date.strftime(deb_changelog_format_string)
for changelog_file in changelog_files:
    with open(changelog_file, 'r') as file:
        print('Bumping version in ' + changelog_file)
        filedata = file.read()
        type=re.search(r'(wazuh-(agent|manager|indexer|dashboard))', filedata).group(1)
        changelog_string="wazuh-{} ({}-RELEASE) stable; urgency=low\n\n  * More info: https://documentation.wazuh.com/current/release-notes/release-{}-{}-{}.html\n\n -- Wazuh, Inc <info@wazuh.com>  {}\n\n".format(type, version, version.major, version.minor, version.micro, deb_changelog_date)
        # Add new version to changelog
        filedata = changelog_string + filedata
        
    with open(changelog_file, 'w') as file:
        file.write(filedata)

## Bump version in pkginfo files

pkginfo_format_string = "%d%b%Y"

for pkginfo_file in pkginfo_files:
    with open(pkginfo_file, 'r') as file:
        print('Bumping version in ' + pkginfo_file)
        filedata = file.read()
        # Replace version and revision
        regex = r'VERSION=(\d+\.\d+\.\d+)'
        filedata = re.sub(regex, 'VERSION=\"{}\"'.format(version), filedata)
        regex = r'PSTAMP=(.*)'
        filedata = re.sub(regex, 'PSTAMP=\"{}\"'.format(date.strftime(pkginfo_format_string)), filedata)

    with open(pkginfo_file, 'w') as file:
        file.write(filedata)

## Bump version in .pkgproj files

for pkgproj_file in pkgproj_files:
    with open(pkgproj_file, 'r') as file:
        print('Bumping version in ' + pkgproj_file)
        filedata = file.read()
        # Replace version and revision
        regex = r'<string>(\d+\.\d+\.\d+)-(\d+)</string>'
        filedata = re.sub(regex, '<string>{}-{}</string>'.format(version, args.revision), filedata)
        regex = r'<string>wazuh-agent-(\d+\.\d+\.\d+)-(\d+)</string>'
        filedata = re.sub(regex, '<string>wazuh-agent-{}-{}</string>'.format(version, args.revision), filedata)

    with open(pkgproj_file, 'w') as file:
        file.write(filedata)

## Bump version in test-*.sh files

for test_file in test_files:
    with open(test_file, 'r') as file:
        print('Bumping version in ' + test_file)
        filedata = file.read()
        # Replace version and revision
        regex = r'wazuh-manager.x86_64\s+(\d+\.\d+\.\d+)-(\d+)'
        filedata = re.sub(regex, 'wazuh-manager.x86_64 {}-{}'.format(version, args.revision), filedata)
        regex = r'wazuh_version=\"(\d+\.\d+\.\d+)\"'
        filedata = re.sub(regex, 'wazuh_version=\"{}\"'.format(version), filedata)

    with open(test_file, 'w') as file:
        file.write(filedata)

## Bump version in installVariables.sh files

for install_variables_file in install_variables_files:
    with open(install_variables_file, 'r') as file:
        print('Bumping version in ' + install_variables_file)
        filedata = file.read()
        # Replace version and revision
        regex = r'wazuh_major=\"(\d+\.\d+)\"'
        filedata = re.sub(regex, 'wazuh_major=\"{}.{}\"'.format(version.major,version.minor), filedata)
        regex = r'wazuh_version=\"(\d+\.\d+\.\d+)\"'
        filedata = re.sub(regex, 'wazuh_version=\"{}\"'.format(version), filedata)
    
    with open(install_variables_file, 'w') as file:
        file.write(filedata)
        