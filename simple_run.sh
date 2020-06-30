VERSION="v0.0.1"
#generate docker file
sed "s/\$VERSION/${VERSION}/g" ./DockerfileTemplate > ./Dockerfile
#build angr-timer
sudo docker image build -t angr-timer .
#run angr-timer
sudo docker run --rm -it angr-timer