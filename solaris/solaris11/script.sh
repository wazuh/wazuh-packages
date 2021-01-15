#!/bin/sh
# IPS Duty Script to detect and run postinstall-* and postremove-* scripts
# in /var/lib/wazuh-install/postaction
###
# This is a prototype version. Support is not provided.
# Detlef.Drewanz@oracle.com, v0.1, 22.07.2017

SVC=wazuh-install
DIR=/var/ossec
LIBDIR=/var/ossec
BART=/usr/bin/bart
# The directory, where the postinstall-* and postremove-* scripts are found
POSTACTION=${LIBDIR}/postaction
# The cache directory for executed postinstall and to be executed postremove
CACHE=${LIBDIR}/cache

# First create bart manifests of the postaction and the cache directory.
${BART} create -R ${POSTACTION} > ${LIBDIR}/postaction.manifest
${BART} create -R ${CACHE} > ${LIBDIR}/cache.manifest

# Now compare and check for todo's
${BART} compare -p -r ${DIR}/bart.rule ${LIBDIR}/cache.manifest ${LIBDIR}/postaction.manifest | \
while read filename todo;
do
  case "${todo}" in
    "add")
        # Ok, this entry is not in cache already
        # If it's a postinstall*, do it now
        # Then copy the file always to cache
        touch /test
        INSTALL=`echo ${filename} | grep ^/postinstall.sh`
        if [ -n "${INSTALL}" ]; then
          ${POSTACTION}${filename}
        fi
        cp -p ${POSTACTION}${filename} ${CACHE}
        ;;
    "delete")
        # Ok, this entry is in cache, but no longer in postaction
        # If it's a postremove-*, do it now
        # Then remove the file always from cache
        # REMOVE=`echo ${filename} | grep ^/postremove-`
        # if [ -n "${REMOVE}" ]; then
        #   ${CACHE}${filename}
        # fi
        # rm ${CACHE}${filename}
        ;;
    *)
        # Ok, this entry is in cache already, but has been modified recently
        # So copy the file always to cache
        cp -p ${POSTACTION}${filename} ${CACHE}
        ;;
  esac
done
# Finally remove the bart manifests
# rm ${LIBDIR}/postaction.manifest
# rm ${LIBDIR}/cache.manifest

# Exit SMF
exit 0