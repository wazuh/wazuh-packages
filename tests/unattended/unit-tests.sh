trap clean SIGINT

logfile="/var/log/unit-tests-wazuh-installer.log"
debug=">/dev/null"

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

    eval "docker exec $container_name bash -lc \"cd /tests/unattended && bash test-$1.sh\""
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

main() {

    if [ -z "$(command -v docker)" ]; then
        echo "Error: Docker must be installed in the system to run the tests"
        exit 1
    fi

    if [ "$#" -eq 0 ]; then
        all_tests=1
    fi

    createImage
    runContainer
    if [ -n "$all_tests" ] || [ "$1" == "common" ]; then
        testFile common
    fi
    if [ -n "$all_tests" ] || [ "$1" == "checks" ]; then
        testChecks checks
    fi
    clean
}

main $@