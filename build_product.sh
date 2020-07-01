VERSION="v0.0.1"
#build
sudo docker image build -t angr-timer-product:${VERSION} -f Dockerfile.product .
#run
sudo docker run --rm -it angr-timer-product:${VERSION}