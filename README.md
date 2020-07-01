### 构建docker环境 
./build_env.sh 或者 make 
### 修改代码后构建并启动开发容器
./simple_run.sh
### 构建并启动生产环境容器
./run_product.sh


### for copy use
sudo docker cp container:/home/angr/angr-dev/angr/angr ~/angr_timer/code/angr-dev/  
sudo docker cp container:/home/angr/angr-dev/claripy/claripy ~/angr_timer/code/angr-dev/  
chmod a+w,a+r -R code/angr-dev/angr  
chmod a+w,a+r -R code/angr-dev/claripy  


