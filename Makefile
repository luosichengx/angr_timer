VERSION=v0.0.1
WITH_MODEL=true
ANGR_DEP_IMAGE=angr-dep
ANGR_IMAGE=angr-dev
ANGR_IMAGE_WITH_MODEL=angr_predict
ANGR_DOCKER_DIR=./angr
ANGR_DEP_DIR=${ANGR_DOCKER_DIR}/angr-dep
MODEL_DIR=./model
MODEL_DEPENDENCY=install_dep.sh

.PHONY:all build_env build_angr_predict build_angr_dependency build_angr_dev clean
all:build_env
build_env:build_angr_predict
build_angr_predict:build_angr_dev ${MODEL_DIR}/DockerfileTemplate
	if [ ${WITH_MODEL} = true ]; then \
    	sed "s/\$\$$VERSION/${VERSION}/g; s/\$\$$MODEL_DEPENDENCY/${MODEL_DEPENDENCY}/g" ${MODEL_DIR}/DockerfileTemplate > ${MODEL_DIR}/Dockerfile; \
    	sudo docker image build -t ${ANGR_IMAGE_WITH_MODEL}:${VERSION} -f ${MODEL_DIR}/Dockerfile .; \
	fi
build_angr_dev:build_angr_dependency ${ANGR_DOCKER_DIR}/Dockerfile
	sudo docker image build -t ${ANGR_IMAGE}:${VERSION} -f ${ANGR_DOCKER_DIR}/Dockerfile .
build_angr_dependency:${ANGR_DEP_DIR}/Dockerfile
	sudo docker image build -t ${ANGR_DEP_IMAGE} -f ${ANGR_DEP_DIR}/Dockerfile .
clean:
	sudo docker rmi -f ${ANGR_DEP_IMAGE} ${ANGR_IMAGE}:${VERSION} ${ANGR_IMAGE_WITH_MODEL}:${VERSION}