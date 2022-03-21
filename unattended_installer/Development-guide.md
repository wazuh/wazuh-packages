Wazuh unattended installer - Development guide
========================================

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

# Development guide

In order to have homogenous developments, this document shows some rules to be taken into account when adding or modifying capabilities. These rules must be taken into account as much as possible.

- Write a function with a single objective.
- Every function must have limited arguments, the less the better.
- The functions should be open for extension but closed for modifications.
- Use libraries (I.e `install_functions`) and load only the necessaries.
- Main functions will not depend on the functions themselves implementation.
- Use descriptive variable names and function names. Avoid mind-mapping, a clean code is itself commented. Use comments only in necessary cases.
- Use Read-only to declare static variables.
- Use `$(command)` instead of classic `` `command` ``.
- Use `${var}` instead of `$(var)`.
- Variables should always be quoted: `"${var}"`.
- Use logger function instead of `echo`.
- Prevent commands from failure by catching the result of a command with `$?`.
- Take control of every possible long command setting up timeouts.
- Every needed resource must be obtained (on-line and off-line). This resource must be checked if exist in the desired path (libraries).
- Use `command -v` for commands exist checking.
- Parametrize all packages versions.
- Use `| grep -q` instead of `| grep`
- Use standard `$((..))` instead of old `$[]`

*Additional check*: Run unit [tests](/tests/unattended/unit/README) before preparing a pull request.

## License and copyright

Copyright (C) 2015, Wazuh Inc.

This program is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public
License (version 2) as published by the FSF - Free Software
Foundation.

## Useful links and acknowledgment

- [Bash meets solid](https://codewizardly.com/bash-meets-solid/)
- [Shellcheck](https://github.com/koalaman/shellcheck#gallery-of-bad-code)
