from angr-dev:v0.0.1

COPY model/install_dep.sh /home/angr/install_dep.sh
run chown angr /home/angr/install_dep.sh && chmod +x /home/angr/install_dep.sh
run su - angr -c "./install_dep.sh"
cmd su - angr