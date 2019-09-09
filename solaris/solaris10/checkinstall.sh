# cat checkinstall
#!/bin/sh

expected_platform="i386"
platform=`uname -p`
if [ ${platform} != ${expected_platform} ]; then
        echo "This package must be installed on ${platform}"
        exit
fi
exit 0
