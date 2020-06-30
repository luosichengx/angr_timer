### 构建docker环境 
./build_env.sh 或者 make
### 运行angr-timer容器 
sudo docker run -it angr_predict:v0.0.1 
### 修改代码后构建并启动容器
./simple_run.sh


### for copy use
sudo docker cp container:/home/angr/angr-dev/angr/angr ~/angr_timer/code/angr-dev/
sudo docker cp container:/home/angr/angr-dev/claripy/angr ~/angr_timer/code/angr-dev/

