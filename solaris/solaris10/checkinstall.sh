# cat checkinstall
#!/bin/sh

expected_platform="x86_64"
platform=`uname -p`
if [ ${platform} != ${expected_platform} ]; then
        echo "This package must be installed on ${expected_platform}"
        exit
fi
exit 0
