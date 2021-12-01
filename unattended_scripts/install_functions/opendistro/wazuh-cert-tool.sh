#!/bin/bash

# Program to generate the certificates necessary for Wazuh installation
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

debug_cert='>> /var/log/wazuh-cert-tool.log 2>&1'
ELASTICINSTANCES="elasticsearch-nodes:"
FILEBEATINSTANCES="wazuh-servers:"
KIBANAINSTANCES="kibana:"
ELASTICHEAD='# Elasticsearch nodes'
FILEBEATHEAD='# Wazuh server nodes'
KIBANAHEAD='# Kibana node'

## Prints information
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
    echo $now $mtype $message | tee /var/log/wazuh-cert-tool.log
}

readInstances() {

    if [ -f ${base_path}/instances.yml ]; then
        logger "Configuration file found. Creating certificates..."
        eval "mkdir ${base_path}/certs $debug"
    else
        logger_cert -e "No configuration file found."
        exit 1;
    fi

    readFile

}

getHelp() {
    echo ""
    echo "Usage: $0 arguments"
    echo -e "\t-a     | --admin-certificates Creates the admin certificates."
    echo -e "\t-ca    | --root-ca-certificates Creates the root-ca certificates."
    echo -e "\t-a     | --elasticsearch-certificates Creates the Elasticsearch certificates."
    echo -e "\t-w     | --wazuh-certificates Creates the Wazuh server certificates."
    echo -e "\t-k     | --kibana-certificates Creates the Kibana certificates."
    echo -e "\t-d     | --debug Enables verbose mode."
    exit 1 # Exit script after printing help    
}

readFile() {

    IFS=$'\r\n' GLOBIGNORE='*' command eval  'INSTANCES=($(cat ${base_path}/instances.yml))'
    for i in "${!INSTANCES[@]}"; do
    if [[ "${INSTANCES[$i]}" == "${ELASTICINSTANCES}" ]]; then
        ELASTICLIMITT=${i}
    fi
        if [[ "${INSTANCES[$i]}" == "${FILEBEATINSTANCES}" ]]; then
        ELASTICLIMIB=${i}
    fi

    if [[ "${INSTANCES[$i]}" == "${FILEBEATINSTANCES}" ]]; then
        FILEBEATLIMITT=${i}
    fi
    
    if [[ "${INSTANCES[$i]}" == "${KIBANAINSTANCES}" ]]; then
        FILEBEATLIMIB=${i}
    fi  
    done

    ## Read Elasticsearch nodes
    counter=${ELASTICLIMITT}
    i=0
    while [ "${counter}" -le "${ELASTICLIMIB}" ]
    do
        if  [ "${INSTANCES[counter]}" !=  "${ELASTICINSTANCES}" ] && [ "${INSTANCES[counter]}" !=  "${FILEBEATINSTANCES}" ] && [ "${INSTANCES[counter]}" !=  "${FILEBEATHEAD}" ] && [ "${INSTANCES[counter]}" !=  "    ip:" ] && [ -n "${INSTANCES[counter]}" ]; then
            ELASTICNODES[i]+="$(echo "${INSTANCES[counter]}" | tr -d '\011\012\013\014\015\040')"
            ((i++))
        fi    

        ((counter++))
    done

    ## Read Filebeat nodes
    counter=${FILEBEATLIMITT}
    i=0
    while [ "${counter}" -le "${FILEBEATLIMIB}" ]
    do
        if  [ "${INSTANCES[counter]}" !=  "${FILEBEATINSTANCES}" ] && [ "${INSTANCES[counter]}" !=  "${KIBANAINSTANCES}" ] && [ "${INSTANCES[counter]}" !=  "${KIBANAHEAD}" ] && [ "${INSTANCES[counter]}" !=  "    ip:" ] && [ -n "${INSTANCES[counter]}" ]; then
            FILEBEATNODES[i]+="$(echo "${INSTANCES[counter]}" | tr -d '\011\012\013\014\015\040')"
            ((i++))
        fi    

        ((counter++))
    done

    ## Read Kibana nodes
    counter=${FILEBEATLIMIB}
    i=0
    while [ "${counter}" -le "${#INSTANCES[@]}" ]
    do
        if  [ "${INSTANCES[counter]}" !=  "${KIBANAINSTANCES}" ]  && [ "${INSTANCES[counter]}" !=  "${KIBANAHEAD}" ] && [ "${INSTANCES[counter]}" !=  "    ip:" ] && [ -n "${INSTANCES[counter]}" ]; then
            KIBANANODES[i]+="$(echo "${INSTANCES[counter]}" | tr -d '\011\012\013\014\015\040')"
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

<<<<<<< HEAD
    eval "openssl req -x509 -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/root-ca.key -out ${base_path}/certs/root-ca.pem -batch -subj '/OU=Docu/O=Wazuh/L=California/' -days 3650 ${debug}"
=======
    eval "openssl req -x509 -new -nodes -newkey rsa:2048 -keyout ./certs/root-ca.key -out ./certs/root-ca.pem -batch -subj '/OU=Docu/O=Wazuh/L=California/' -days 3650 ${debug_cert}"
>>>>>>> 6659cda5 (Corrected logger and debug)

}

generateAdmincertificate() {
    
<<<<<<< HEAD
    eval "openssl genrsa -out ${base_path}/certs/admin-key-temp.pem 2048 ${debug}"
    eval "openssl pkcs8 -inform PEM -outform PEM -in ${base_path}/certs/admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out ${base_path}/certs/admin-key.pem ${debug}"
    eval "openssl req -new -key ${base_path}/certs/admin-key.pem -out ${base_path}/certs/admin.csr -batch -subj '/C=US/L=California/O=Wazuh/OU=Docu/CN=admin' ${debug}"
    eval "openssl x509 -req -in ${base_path}/certs/admin.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -sha256 -out ${base_path}/certs/admin.pem ${debug}"
=======
    eval "openssl genrsa -out ./certs/admin-key-temp.pem 2048 ${debug_cert}"
    eval "openssl pkcs8 -inform PEM -outform PEM -in ./certs/admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out ./certs/admin-key.pem ${debug_cert}"
    eval "openssl req -new -key ./certs/admin-key.pem -out ./certs/admin.csr -batch -subj '/C=US/L=California/O=Wazuh/OU=Docu/CN=admin' ${debug_cert}"
    eval "openssl x509 -req -in ./certs/admin.csr -CA ./certs/root-ca.pem -CAkey ./certs/root-ca.key -CAcreateserial -sha256 -out ./certs/admin.pem ${debug_cert}"
>>>>>>> 6659cda5 (Corrected logger and debug)

}

generateElasticsearchcertificates() {

<<<<<<< HEAD
    logger "Creating the Elasticsearch certificates..."
=======
     logger_cert "Creating the Elasticsearch certificates..."
>>>>>>> f8aed672 (Changed logger name in wazuh-cert-tool and wazuh-password-tool)

    i=0
    while [ ${i} -lt ${#ELASTICNODES[@]} ]; do
        cname=${ELASTICNODES[i]}
        cip=${ELASTICNODES[i+1]}
        rname="-name:"
        cname="${cname//$rname}"
        rip="-"
        cip="${cip//$rip}"
        cname=$(echo ${cname} | xargs)
        cip=$(echo ${cip} | xargs)

        generateCertificateconfiguration cname cip
<<<<<<< HEAD
        eval "openssl req -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/${cname}-key.pem -out ${base_path}/certs/${cname}.csr -config ${base_path}/certs/${cname}.conf -days 3650 ${debug}"
        eval "openssl x509 -req -in ${base_path}/certs/${cname}.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -out ${base_path}/certs/${cname}.pem -extfile ${base_path}/certs/${cname}.conf -extensions v3_req -days 3650 ${debug}"
        eval "chmod 444 ${base_path}/certs/${cname}-key.pem ${debug}"    
=======
        eval "openssl req -new -nodes -newkey rsa:2048 -keyout ./certs/${cname}-key.pem -out ./certs/${cname}.csr -config ./certs/${cname}.conf -days 3650 ${debug_cert}"
        eval "openssl x509 -req -in ./certs/${cname}.csr -CA ./certs/root-ca.pem -CAkey ./certs/root-ca.key -CAcreateserial -out ./certs/${cname}.pem -extfile ./certs/${cname}.conf -extensions v3_req -days 3650 ${debug_cert}"
        eval "chmod 444 ./certs/${cname}-key.pem ${debug_cert}"    
>>>>>>> 6659cda5 (Corrected logger and debug)
        i=$(( ${i} + 2 ))
    done

}

generateFilebeatcertificates() {

    logger_cert "Creating Wazuh server certificates..."

    i=0
    while [ ${i} -lt ${#FILEBEATNODES[@]} ]; do
        cname=${FILEBEATNODES[i]}
        cip=${FILEBEATNODES[i+1]}
        rname="-name:"
        cname="${cname//$rname}"
        rip="-"
        cip="${cip//$rip}"
        cname=$(echo ${cname} | xargs)
        cip=$(echo ${cip} | xargs)

        generateCertificateconfiguration cname cip
<<<<<<< HEAD
        eval "openssl req -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/${cname}-key.pem -out ${base_path}/certs/${cname}.csr -config ${base_path}/certs/${cname}.conf -days 3650 ${debug}"
        eval "openssl x509 -req -in ${base_path}/certs/${cname}.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -out ${base_path}/certs/${cname}.pem -extfile ${base_path}/certs/${cname}.conf -extensions v3_req -days 3650 ${debug}"
=======
        eval "openssl req -new -nodes -newkey rsa:2048 -keyout ./certs/${cname}-key.pem -out ./certs/${cname}.csr -config ./certs/${cname}.conf -days 3650 ${debug_cert}"
        eval "openssl x509 -req -in ./certs/${cname}.csr -CA ./certs/root-ca.pem -CAkey ./certs/root-ca.key -CAcreateserial -out ./certs/${cname}.pem -extfile ./certs/${cname}.conf -extensions v3_req -days 3650 ${debug_cert}"
>>>>>>> 6659cda5 (Corrected logger and debug)
        i=$(( ${i} + 2 ))
    done      

}

generateKibanacertificates() {

    logger_cert "Creating Kibana certificate..."

    i=0
    while [ ${i} -lt ${#KIBANANODES[@]} ]; do
        cname=${KIBANANODES[i]}
        cip=${KIBANANODES[i+1]}
        rname="-name:"
        cname="${cname//$rname}"
        rip="-"
        cip="${cip//$rip}"
        cname=$(echo ${cname} | xargs)
        cip=$(echo ${cip} | xargs)

        generateCertificateconfiguration cname cip
<<<<<<< HEAD
        eval "openssl req -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/${cname}-key.pem -out ${base_path}/certs/${cname}.csr -config ${base_path}/certs/${cname}.conf -days 3650 ${debug}"
        eval "openssl x509 -req -in ${base_path}/certs/${cname}.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -out ${base_path}/certs/${cname}.pem -extfile ${base_path}/certs/${cname}.conf -extensions v3_req -days 3650 ${debug}"
=======
        eval "openssl req -new -nodes -newkey rsa:2048 -keyout ./certs/${cname}-key.pem -out ./certs/${cname}.csr -config ./certs/${cname}.conf -days 3650 ${debug_cert}"
        eval "openssl x509 -req -in ./certs/${cname}.csr -CA ./certs/root-ca.pem -CAkey ./certs/root-ca.key -CAcreateserial -out ./certs/${cname}.pem -extfile ./certs/${cname}.conf -extensions v3_req -days 3650 ${debug_cert}"
>>>>>>> 6659cda5 (Corrected logger and debug)
        i=$(( ${i} + 2 ))
    done 

}

cleanFiles() {

<<<<<<< HEAD
    eval "rm -rf ${base_path}/certs/*.csr ${debug}"
    eval "rm -rf ${base_path}/certs/*.srl ${debug}"
    eval "rm -rf ${base_path}/certs/*.conf ${debug}"
    eval "rm -rf ${base_path}/certs/admin-key-temp.pem ${debug}"
    logger "Certificates creation finished. They can be found in ${base_path}/certs."
=======
    eval "rm -rf ./certs/*.csr ${debug_cert}"
    eval "rm -rf ./certs/*.srl ${debug_cert}"
    eval "rm -rf ./certs/*.conf ${debug_cert}"
    eval "rm -rf ./certs/admin-key-temp.pem ${debug_cert}"
<<<<<<< HEAD
    logger "Certificates creation finished. They can be found in ./certs."
>>>>>>> 6659cda5 (Corrected logger and debug)
=======
    logger_cert "Certificates creation finished. They can be found in ./certs."
>>>>>>> f8aed672 (Changed logger name in wazuh-cert-tool and wazuh-password-tool)

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
            "-d"|"--debug") 
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
            debug_cert='2>&1 | tee -a /var/log/wazuh-cert-tool.log'          
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

main @
