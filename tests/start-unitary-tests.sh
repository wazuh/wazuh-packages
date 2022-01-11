function createDocker() {

    if [ ! -f ./Dockerfile ]; then
        echo "Error: No Dockerfile found to create the environment"
    fi

    image_name="testing-img"
    eval "docker build -t $image_name ."
    container_name="testing-container"
    eval "docker run -d -t --name $container_name $image_name /bin/bash "
    container_id="$( docker ps -a | grep $container_name | awk '{ print $1 }' )"
}

function testCommon() {
    eval "mkdir temp/"
    eval "cp ../unattended_scripts/install_functions/opendistro/common.sh temp/"
    eval "docker cp temp/common.sh $container_id:/tests/unattended/common.sh"
    eval "docker exec $container_name bash -c \"cd /tests/unattended && bash test-common.sh\" "
}

function clean() {
    eval "docker stop $container_name"
    eval "docker rm $container_name"
    eval "docker rmi $image_name"
    eval "rm -rf temp/"
}

main() {

    if [ "$EUID" -ne 0 ]; then
        logger -e "Error: This script must be run as root."
        exit 1
    fi

    if [ -z "$(command -v docker)" ]; then
        echo "Error: Docker must be installed in the system to run the tests"
        exit 1
    fi

    createDocker
    testCommon
    clean
}

main