#!/bin/bash

wpk_name="$1"
package_version="$2"

echo -ne "v${package_version} $(sha1sum ${wpk_name} | cut -d' ' -f1)\n$(grep -hv "v${package_version} " ./versions 2>/dev/null)" > ./versions