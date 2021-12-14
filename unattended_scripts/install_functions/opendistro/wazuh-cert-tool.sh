#!/bin/bash

# Program to generate the certificates necessary for Wazuh installation
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

if [[ -z "${logfile}" ]]; then
    logfile="/var/log/wazuh-cert-tool.log"
fi
debug_cert=">> ${logfile} 2>&1"
elasticinstances="elasticsearch-nodes:"
filebeatinstances="wazuh-servers:"
kibanainstances="kibana:"
elastichead='# Elasticsearch nodes'
filebeathead='# Wazuh server nodes'
kibanahead='# Kibana node'

logger_cert() {

    now=$(date +'%m/%d/%Y %H:%M:%S')
    case $1 in 
        "-e")
            mtype="ERROR:"
            message="$2"
            ;;
        "-w")
            mtype="WARNING:"
            message="$2"
            ;;
        *)
            mtype="INFO:"
            message="$1"
            ;;
    esac
    echo $now $mtype $message | tee -a ${logfile}
}

readInstances() {

    if [ -f ${base_path}/instances.yml ]; then
        logger_cert "Configuration file found. Creating certificates..."
        eval "mkdir ${base_path}/certs $debug"
    else
        logger_cert -e "No configuration file found."
        exit 1;
    fi

    readFile

}

getHelp() {
    echo -e ""
    echo -e "NAME"
    echo -e "        wazuh-cert-tool.sh - Manages the creation of certificates of the Wazuh components."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        wazuh-cert-tool.sh [OPTIONS]"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --admin-certificates"
    echo -e "                Creates the admin certificates."
    echo -e ""
    echo -e "        -ca, --root-ca-certificates"
    echo -e "                Creates the root-ca certificates."
    echo -e ""
    echo -e "        -e,  --elasticsearch-certificates"
    echo -e "                Creates the Elasticsearch certificates."
    echo -e ""
    echo -e "        -w,  --wazuh-certificates"
    echo -e "                Creates the Wazuh server certificates."
    echo -e ""
    echo -e "        -k,  --kibana-certificates"
    echo -e "                Creates the Kibana certificates."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Enables verbose mode."
    exit 1
}

readFile() {

    IFS=$'\r\n' GLOBIGNORE='*' command eval  'instances=($(cat ${base_path}/instances.yml))'
    for i in "${!instances[@]}"; do
    if [[ "${instances[$i]}" == "${elasticinstances}" ]]; then
        elasticlimitt=${i}
    fi
        if [[ "${instances[$i]}" == "${filebeatinstances}" ]]; then
        elasticlimib=${i}
    fi

    if [[ "${instances[$i]}" == "${filebeatinstances}" ]]; then
        filebeatlimitt=${i}
    fi
    
    if [[ "${instances[$i]}" == "${kibanainstances}" ]]; then
        filebeatlimib=${i}
    fi  
    done

    ## Read Elasticsearch nodes
    counter=${elasticlimitt}
    i=0
    while [ "${counter}" -le "${elasticlimib}" ]
    do
        if  [ "${instances[counter]}" !=  "${elasticinstances}" ] && [ "${instances[counter]}" !=  "${filebeatinstances}" ] && [ "${instances[counter]}" !=  "${filebeathead}" ] && [ "${instances[counter]}" !=  "    ip:" ] && [ -n "${instances[counter]}" ]; then
            elasticnodes[i]+="$(echo "${instances[counter]}" | tr -d '\011\012\013\014\015\040')"
            ((i++))
        fi    

        ((counter++))
    done

    ## Read Filebeat nodes
    counter=${filebeatlimitt}
    i=0
    while [ "${counter}" -le "${filebeatlimib}" ]
    do
        if  [ "${instances[counter]}" !=  "${filebeatinstances}" ] && [ "${instances[counter]}" !=  "${kibanainstances}" ] && [ "${instances[counter]}" !=  "${kibanahead}" ] && [ "${instances[counter]}" !=  "    ip:" ] && [ -n "${instances[counter]}" ]; then
            filebeatnodes[i]+="$(echo "${instances[counter]}" | tr -d '\011\012\013\014\015\040')"
            ((i++))
        fi    

        ((counter++))
    done

    ## Read Kibana nodes
    counter=${filebeatlimib}
    i=0
    while [ "${counter}" -le "${#instances[@]}" ]
    do
        if  [ "${instances[counter]}" !=  "${kibanainstances}" ]  && [ "${instances[counter]}" !=  "${kibanahead}" ] && [ "${instances[counter]}" !=  "    ip:" ] && [ -n "${instances[counter]}" ]; then
            kibananodes[i]+="$(echo "${instances[counter]}" | tr -d '\011\012\013\014\015\040')"
            ((i++))
        fi    

        ((counter++))    
    done

}


generateCertificateconfiguration() {

    cat > ${base_path}/certs/${cname}.conf <<- EOF
        [ req ]
        prompt = no
        default_bits = 2048
        default_md = sha256
        distinguished_name = req_distinguished_name
        x509_extensions = v3_req
        
        [req_distinguished_name]
        C = US
        L = California
        O = Wazuh
        OU = Docu
        CN = cname
        
        [ v3_req ]
        authorityKeyIdentifier=keyid,issuer
        basicConstraints = CA:FALSE
        keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
        subjectAltName = @alt_names
        
        [alt_names]
        IP.1 = cip
	EOF

    conf="$(awk '{sub("CN = cname", "CN = '${cname}'")}1' ${base_path}/certs/$cname.conf)"
    echo "${conf}" > ${base_path}/certs/$cname.conf    

    isIP=$(echo "${cip}" | grep -P "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
    isDNS=$(echo ${cip} | grep -P "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$" )

    if [[ -n "${isIP}" ]]; then
        conf="$(awk '{sub("IP.1 = cip", "IP.1 = '${cip}'")}1' ${base_path}/certs/$cname.conf)"
        echo "${conf}" > ${base_path}/certs/$cname.conf    
    elif [[ -n "${isDNS}" ]]; then
        conf="$(awk '{sub("CN = cname", "CN =  '${cip}'")}1' ${base_path}/certs/$cname.conf)"
        echo "${conf}" > ${base_path}/certs/$cname.conf     
        conf="$(awk '{sub("IP.1 = cip", "DNS.1 = '${cip}'")}1' ${base_path}/certs/$cname.conf)"
        echo "${conf}" > ${base_path}/certs/$cname.conf 
    else
        logger_cert -e "The given information does not match with an IP or a DNS"  
        exit 1; 
    fi   

}

generateRootCAcertificate() {

    eval "openssl req -x509 -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/root-ca.key -out ${base_path}/certs/root-ca.pem -batch -subj '/OU=Docu/O=Wazuh/L=California/' -days 3650 ${debug_cert}"

}

generateAdmincertificate() {
    
    eval "openssl genrsa -out ${base_path}/certs/admin-key-temp.pem 2048 ${debug_cert}"
    eval "openssl pkcs8 -inform PEM -outform PEM -in ${base_path}/certs/admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out ${base_path}/certs/admin-key.pem ${debug_cert}"
    eval "openssl req -new -key ${base_path}/certs/admin-key.pem -out ${base_path}/certs/admin.csr -batch -subj '/C=US/L=California/O=Wazuh/OU=Docu/CN=admin' ${debug_cert}"
    eval "openssl x509 -req -in ${base_path}/certs/admin.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -sha256 -out ${base_path}/certs/admin.pem ${debug_cert}"

}

generateElasticsearchcertificates() {

     logger_cert "Creating the Elasticsearch certificates..."

    i=0
    while [ ${i} -lt ${#elasticnodes[@]} ]; do
        cname=${elasticnodes[i]}
        cip=${elasticnodes[i+1]}
        rname="-name:"
        cname="${cname//$rname}"
        rip="-"
        cip="${cip//$rip}"
        cname=$(echo ${cname} | xargs)
        cip=$(echo ${cip} | xargs)

        generateCertificateconfiguration cname cip
        eval "openssl req -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/${cname}-key.pem -out ${base_path}/certs/${cname}.csr -config ${base_path}/certs/${cname}.conf -days 3650 ${debug_cert}"
        eval "openssl x509 -req -in ${base_path}/certs/${cname}.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -out ${base_path}/certs/${cname}.pem -extfile ${base_path}/certs/${cname}.conf -extensions v3_req -days 3650 ${debug_cert}"
        eval "chmod 444 ${base_path}/certs/${cname}-key.pem ${debug_cert}"    
       i=$(( ${i} + 2 ))
    done

}

generateFilebeatcertificates() {

    logger_cert "Creating Wazuh server certificates..."

    i=0
    while [ ${i} -lt ${#filebeatnodes[@]} ]; do
        cname=${filebeatnodes[i]}
        cip=${filebeatnodes[i+1]}
        rname="-name:"
        cname="${cname//$rname}"
        rip="-"
        cip="${cip//$rip}"
        cname=$(echo ${cname} | xargs)
        cip=$(echo ${cip} | xargs)

        generateCertificateconfiguration cname cip
        eval "openssl req -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/${cname}-key.pem -out ${base_path}/certs/${cname}.csr -config ${base_path}/certs/${cname}.conf -days 3650 ${debug_cert}"
        eval "openssl x509 -req -in ${base_path}/certs/${cname}.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -out ${base_path}/certs/${cname}.pem -extfile ${base_path}/certs/${cname}.conf -extensions v3_req -days 3650 ${debug_cert}"
       i=$(( ${i} + 2 ))
    done      

}

generateKibanacertificates() {

    logger_cert "Creating Kibana certificate..."

    i=0
    while [ ${i} -lt ${#kibananodes[@]} ]; do
        cname=${kibananodes[i]}
        cip=${kibananodes[i+1]}
        rname="-name:"
        cname="${cname//$rname}"
        rip="-"
        cip="${cip//$rip}"
        cname=$(echo ${cname} | xargs)
        cip=$(echo ${cip} | xargs)

        generateCertificateconfiguration cname cip
        eval "openssl req -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/${cname}-key.pem -out ${base_path}/certs/${cname}.csr -config ${base_path}/certs/${cname}.conf -days 3650 ${debug_cert}"
        eval "openssl x509 -req -in ${base_path}/certs/${cname}.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -out ${base_path}/certs/${cname}.pem -extfile ${base_path}/certs/${cname}.conf -extensions v3_req -days 3650 ${debug_cert}"
       i=$(( ${i} + 2 ))
    done 

}

cleanFiles() {

    eval "rm -rf ${base_path}/certs/*.csr ${debug_cert}"
    eval "rm -rf ${base_path}/certs/*.srl ${debug_cert}"
    eval "rm -rf ${base_path}/certs/*.conf ${debug_cert}"
    eval "rm -rf ${base_path}/certs/admin-key-temp.pem ${debug_cert}"
    logger_cert "Certificates creation finished. They can be found in ${base_path}/certs."
}

main() {

    if [ "$EUID" -ne 0 ]; then
        logger_cert -e "This script must be run as root."
        exit 1;
    fi    

    if [ -n "$1" ]; then      
        while [ -n "$1" ]
        do
            case "$1" in 
            "-a"|"--admin-certificates") 
                cadmin=1
                shift 1
                ;;     
            "-ca"|"--root-ca-certificate") 
                ca=1
                shift 1
                ;;                           
            "-e"|"--elasticsearch-certificates") 
                celastic=1
                shift 1
                ;; 
            "-w"|"--wazuh-certificates") 
                cwazuh=1
                shift 1
                ;;   
            "-k"|"--kibana-certificates") 
                ckibana=1
                shift 1
                ;;                               
            "-v"|"--verbose") 
                debugEnabled=1          
                shift 1
                ;;                                 
            "-h"|"--help")        
                getHelp
                ;;                                         
            *)
                getHelp
            esac
        done    

        if [ -n "${debugEnabled}" ]; then
            debug_cert="2>&1 | tee -a ${logfile}"          
        fi

        if [[ -n "${cadmin}" ]]; then
            generateAdmincertificate
            logger_cert "Admin certificates created."
        fi   

        if [[ -n "${ca}" ]]; then
            generateRootCAcertificate
            logger_cert "Authority certificates created."
        fi                   

        if [[ -n "${celastic}" ]]; then
            generateElasticsearchcertificates
            logger_cert "Elasticsearch certificates created."
        fi     

        if [[ -n "${cwazuh}" ]]; then
            generateFilebeatcertificates
            logger_cert "Wazuh server certificates created."
        fi 

        if [[ -n "${ckibana}" ]]; then
            generateKibanacertificates
            logger_cert "Kibana certificates created."
        fi                     
           
    else
        readInstances
        generateRootCAcertificate
        generateAdmincertificate
        generateElasticsearchcertificates
        generateFilebeatcertificates
        generateKibanacertificates
        cleanFiles
    fi

}

main $@
