trap clean SIGINT

logfile="./unit-tests.log"
echo "-------------------------" >> ./unit-tests.log
debug=">> ${logfile}"
ALL_FILES=("common" "checks" "wazuh")

function logger() {

    now=$(date +'%d/%m/%Y %H:%M:%S')
    case ${1} in 
        "-e")
            mtype="ERROR:"
            message="${2}"
            ;;
        "-w")
            mtype="WARNING:"
            message="${2}"
            ;;
        *)
            mtype="INFO:"
            message="${1}"
            ;;
    esac
    echo "${now} ${mtype} ${message}" | tee -a ${logfile}

}


function createImage() {

    if [ ! -f ./Dockerfile ]; then
        logger -e "No Dockerfile found to create the environment."
        exit 1
    fi

    image_name="testing-img"
    if [ -z "$(docker images | grep $image_name)" ]; then
        eval "docker build -t $image_name . ${debug}"
        if [ "$?" != 0 ]; then
            logger -e "Docker encountered some error."
            exit 1
        else 
            logger "Docker image created successfully."
        fi
    else 
        logger "Docker image found."
    fi
}

function runContainer() {
    container_name="testing-container"
    eval "docker run -d -t --name $container_name $image_name /bin/bash ${debug}"
    if [ "$?" != 0 ]; then
        logger -e "Docker encountered some error."
        exit 1
    else 
        logger "Docker container created successfully."
    fi
    container_id="$( docker ps -a | grep $container_name | awk '{ print $1 }' )"
    eval "docker cp bach.sh $container_id:/tests/unattended/bach.sh ${debug}"
    if [ "$?" != 0 ]; then
        logger -e "Error copying bach.sh to the container."
        exit 1
    fi
}

function testFile() {

    logger "Unit tests for $1.sh."

    eval "docker cp test-$1.sh $container_id:/tests/unattended/test-$1.sh ${debug}"
    if [ "$?" != 0 ]; then
        logger -e "File test-$1.sh could not be copied to the container."
        return
    fi
    eval "mkdir -p temp/ ${debug}"

    if [ -f ../../unattended_installer/install_functions/opendistro/$1.sh ]; then
        eval "cp ../../unattended_installer/install_functions/opendistro/$1.sh temp/ ${debug}"
    elif [ -f ../../unattended_installer/install_functions/elasticsearch_basic/$1.sh ]; then
        eval "cp ../../unattended_installer/install_functions/elasticsearch_basic/$1.sh temp/ ${debug}"
    elif [ -f ../../unattended_installer/$1.sh ]; then
        eval "cp ../../unattended_installer/$1.sh ${debug}"
    else 
        logger -e "File $1.sh could not be found."
        return
    fi
    
    eval "docker cp temp/$1.sh $container_id:/tests/unattended/$1.sh ${debug}"
    if [ "$?" != 0 ]; then
        logger -e "File $1.sh could not be copied to the container."
        return
    fi

    eval "docker exec -it $container_name env TERM=xterm-256color bash -c \"cd /tests/unattended && bash test-$1.sh\" | tee -a ${logfile}"
    if [ "$?" != 0 ]; then
        logger -e "Docker encountered some error running the unit tests for $1.sh"
    else 
        logger "All unit tests for the functions in $1.sh finished."
    fi
}

function clean() {
    logger "Cleaning container and temporary files."
    eval "docker stop $container_name ${debug}"
    eval "docker rm $container_name ${debug}"
    eval "rm -rf temp/ ${debug}"
}

function getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "$0") - Unit test for the Wazuh installer."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        bash $(basename "$0") [OPTIONS] -a | -d | -f <file-list>"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --test-all"
    echo -e "                Test all files."
    echo -e ""
    echo -e "        -f,  --files <file-list>"
    echo -e "                List of files to test. I.e. -f common checks"
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    echo -e "        -d,  --debug"
    echo -e "                Shows the complete installation output."
    echo -e ""
    exit 1

}

main() {

    if [ -z "${1}" ]; then
        echo "No argument detected"
        getHelp
    fi

    while [ -n "${1}" ]
    do
        case "${1}" in
            "-a"|"--test-all")
                all_tests=1
                shift 1
                ;;
            "-f"|"--files")
                shift 1
                TEST_FILES=()
                while [ -n "$(echo ${ALL_FILES[@]} | grep -w "${1}")" ]; do
                    TEST_FILES+=("${1}")
                    shift 1
                done
                ;;
            "-d"|"--debug")
                debug="| tee -a ${logfile}"
                shift 1
                ;;
            "-h"|"--help")
                getHelp
                ;;
            *)
                echo "Unknow option: ${1}"
                getHelp
        esac
    done

    if [ -n "${all_tests}" ] && [ ${#TEST_FILES[@]} -gt 0 ]; then
        logger -e "Cannot use options -a and -f in the same run."
        exit 1
    fi

    if [ -z "$(command -v docker)" ]; then
        echo "Error: Docker must be installed in the system to run the tests"
        exit 1
    fi

    createImage
    runContainer

    if [ -n "$all_tests" ]; then
        for file in "${ALL_FILES[@]}"; do
            testFile $file
        done
    else 
        for file in "${TEST_FILES[@]}"; do
            testFile $file
        done
    fi
    clean
}

main $@