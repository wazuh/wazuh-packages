trap clean SIGINT

today="$(date +"%d_%m_%y")"
logfile="./${today}-unit_test.log"
echo "-------------------------" >> ${logfile}
debug=">> ${logfile}"
install_files=("checks" "dashboard" "filebeat" "indexer" "installCommon" "manager")
cert_files=("certFunctions")
passwords_files=("passwordsFunctions")
common_files=("common")
install_dir="install_functions"
cert_dir="cert_tool"
passwords_dir="passwords_tool"
common_dir="common_functions"
IMAGE_NAME="unattended-installer-unit-tests-launcher"
SHARED_VOLUME="$(pwd -P)/tmp/"

function common_logger() {

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
    echo "${message}"
    echo "${now} ${mtype} ${message}" >> ${logfile}

}


function createImage() {

    if [ ! -f docker-unit-testing-tool/Dockerfile ]; then
        common_logger -e "No Dockerfile found to create the environment."
        exit 1
    fi

    if [ -n "${rebuild_image}" ]; then
        common_logger "Removing old image."
        eval "docker rmi ${IMAGE_NAME} ${debug}"
    fi

    if [ -z "$(docker images | grep ${IMAGE_NAME})" ]; then
        common_logger "Building image."
        eval "docker build -t ${IMAGE_NAME} docker-unit-testing-tool ${debug}"
        if [ "$?" != 0 ]; then
            common_logger -e "Docker encountered some error."
            exit 1
        else 
            common_logger "Docker image built successfully."
        fi
    else
        common_logger "Docker image found."
    fi
    eval "mkdir -p ${SHARED_VOLUME} ${debug}"
    eval "cp framework/bach.sh ${SHARED_VOLUME} ${debug}"
}

function testFile() {

    common_logger "Unit tests for ${1}.sh."

    eval "cp suites/test-${1}.sh ${SHARED_VOLUME}"
    if printf '%s\n' "${install_files[@]}" | grep -F -x -q "${1}" ; then
        eval "cp ../../../unattended_installer/${install_dir}/${1}.sh ${SHARED_VOLUME} ${debug}"
    elif printf '%s\n' "${passwords_files[@]}" | grep -F -x -q "${1}"; then
        eval "cp ../../../unattended_installer/${passwords_dir}/${1}.sh ${SHARED_VOLUME} ${debug}"
    elif printf '%s\n' "${cert_files[@]}" | grep -F -x -q "${1}"; then
        eval "cp ../../../unattended_installer/${cert_dir}/${1}.sh ${SHARED_VOLUME} ${debug}"
    elif printf '%s\n' "${common_files[@]}" | grep -F -x -q "${1}"; then
        eval "cp ../../../unattended_installer/${common_dir}/${1}.sh ${SHARED_VOLUME} ${debug}"
    else
        common_logger -e "File ${1}.sh could not be found."
        return
    fi

    eval "docker run -t --rm --volume ${SHARED_VOLUME}:/tests/unattended/ --env TERM=xterm-256color ${IMAGE_NAME} ${1} | tee -a ${logfile}"
    if [ "$?" != 0 ]; then
        common_logger -e "Docker encountered some error running the unit tests for ${1}.sh"
    else 
        common_logger "All unit tests for the functions in ${1}.sh finished."
    fi
}

function clean() {
    common_logger "Cleaning temporary files."
    eval "rm -rf ${SHARED_VOLUME} ${debug}"
}

function getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "${0}") - Unit test for the Wazuh installer."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        bash $(basename "${0}") [OPTIONS] -a | -d | -f <file-list>"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --test-all"
    echo -e "                Test all files."
    echo -e ""
    echo -e "        -d,  --debug"
    echo -e "                Shows the complete installation output."
    echo -e ""
    echo -e "        -f,  --files <file-list>"
    echo -e "                Test one or more files. I.e. -f common checks"
    echo -e "                List of possible files: ${ALL_FILES[@]}"
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    echo -e "        -r,  --rebuild-image"
    echo -e "                Forces to rebuild the image."
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
                while [ -n "${1}" ]; do
                    TEST_FILES+=("${1}")
                    shift 1
                done
                ;;
            "-r"|"--rebuild-image")
                rebuild_image=1
                shift 1
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
        common_logger -e "Cannot use options -a and -f in the same run."
        exit 1
    fi

    if [ -z "$(command -v docker)" ]; then
        echo "Error: Docker must be installed in the system to run the tests"
        exit 1
    fi

    createImage

    if [ -n "${all_tests}" ]; then
        for file in "${install_files[@]}"; do
            testFile ${file}
        done
        for file in "${passwords_file[@]}"; do
            testFile ${file}
        done
        for file in "${cert_file[@]}"; do
            testFile ${file}
        done
        for file in "${common_file[@]}"; do
            testFile ${file}
        done
    else 
        for file in "${TEST_FILES[@]}"; do
            testFile ${file}
        done
    fi
    clean
}

main $@
