FROM angr-dev:v0.0.1

COPY model/install_dep.sh /home/angr/install_dep.sh
RUN chown angr /home/angr/install_dep.sh && chmod +x /home/angr/install_dep.sh
RUN su - angr -c "./install_dep.sh"
RUN su - angr -c "rm ./install_dep.sh"
CMD su - angr
