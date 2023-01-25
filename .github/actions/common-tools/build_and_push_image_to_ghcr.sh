GITHUB_PUSH_SECRET=$1
DOCKER_IMAGE_NAME=$2
BUILD_CONTEXT=$3
DOCKERFILE_PATH="$BUILD_CONTEXT/Dockerfile"
if [ -n "$4" ]; then
    DOCKER_IMAGE_TAG=$4
else 
    DOCKER_IMAGE_TAG="latest"
fi


# Login to GHCR
echo ${GITHUB_PUSH_SECRET} | docker login https://ghcr.io -u "wazuh"--password-stdin

# GITHUB_REPOSITORY is always org/repo syntax. Get the owner in case it is different than the actor (when working in an org)
GITHUB_REPOSITORY="wazuh/wazuh-packages"
GITHUB_OWNER="wazuh"

# Set up full image with tag
IMAGE_ID=ghcr.io/${GITHUB_OWNER}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}
IMAGE_ID=$(echo ${IMAGE_ID} | tr '[A-Z]' '[a-z]')


# Build image
echo build -t ${IMAGE_ID} -f ${DOCKERFILE_PATH} ${BUILD_CONTEXT}
docker build -t ${IMAGE_ID} -f ${DOCKERFILE_PATH} ${BUILD_CONTEXT}

# Push image
if [ "$BUILD_ONLY" == "true" ]; then
    echo "skipping push"
else
    docker push ${IMAGE_ID}
fi