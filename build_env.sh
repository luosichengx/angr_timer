VERSION="v0.0.1"
WITH_MODEL=true
ANGR_DEP_IMAGE="angr-dep"
ANGR_IMAGE="angr-dev"
ANGR_IMAGE_WITH_MODEL="angr_predict"
ANGR_DOCKER_DIR="./angr"
ANGR_DEP_DIR=${ANGR_DOCKER_DIR}"/angr-dep"
MODEL_DIR="./model"
#build angr dependency
echo "sudo docker image build -t ${ANGR_DEP_IMAGE} -f ${ANGR_DEP_DIR}/Dockerfile ."
sudo docker image build -t ${ANGR_DEP_IMAGE} -f ${ANGR_DEP_DIR}/Dockerfile .
#build angr-dev
echo "sudo docker image build -t ${ANGR_IMAGE}:${VERSION} -f ${ANGR_DOCKER_DIR}/Dockerfile ."
sudo docker image build -t ${ANGR_IMAGE}:${VERSION} -f ${ANGR_DOCKER_DIR}/Dockerfile .
#build angr-dev with predict model
echo "sudo docker image build -t ${ANGR_IMAGE_WITH_MODEL}:${VERSION} -f ${MODEL_DIR}/Dockerfile ."
sudo docker image build -t ${ANGR_IMAGE_WITH_MODEL}:${VERSION} -f ${MODEL_DIR}/Dockerfile .