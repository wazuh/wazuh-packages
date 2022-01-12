function startDocker() {

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        eval "systemctl daemon-reload"
        eval "systemctl enable docker.service"
        eval "systemctl start docker.service"
        if [  "$?" != 0  ]; then
            echo "Docker could not be started"
            exit 1
        else 
            echo "Docker started correctly"
        fi
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        eval "chkconfig docker on"
        eval "service docker start"
        eval "/etc/init.d/docker start"
        if [  "$?" != 0  ]; then
            echo "Docker could not be started"
            exit 1
        else 
            echo "Docker started correctly"
        fi
    elif [ -x /etc/rc.d/init.d/docker ] ; then
        eval "/etc/rc.d/init.d/docker start"
        if [  "$?" != 0  ]; then
            echo "Docker could not be started"
            exit 1
        else 
            echo "Docker started correctly"
        fi
    else
        echo "Docker could not be started. No system manager found"
        exit 1
    fi

}

function createDocker() {

    if [ ! -f ./Dockerfile ]; then
        echo "Error: No Dockerfile found to create the environment"
    fi

    image_name="testing-img"
    if [ -z "$(docker images | grep $image_name)" ]; then
        eval "docker build -t $image_name ."
    fi
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
    eval "rm -rf temp/"
}

main() {

    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root."
        exit 1
    fi

    if [ -z "$(command -v docker)" ]; then
        echo "Error: Docker must be installed in the system to run the tests"
        exit 1
    fi

    startDocker
    createDocker
    testCommon
    clean
}

main