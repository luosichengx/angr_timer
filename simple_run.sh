VERSION="v0.0.1"
#generate docker file
sed "s/\$VERSION/${VERSION}/g" ./DockerfileDevTemplate > ./Dockerfile.dev
#build angr-timer
sudo docker image build -t angr-timer:${VERSION} -f Dockerfile.dev .
#run angr-timer
sudo docker run --rm -it angr-timer:${VERSION}