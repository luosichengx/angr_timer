FROM angr_predict:v0.0.1

COPY ./code/angr-dev/angr /home/angr/angr-dev/angr
COPY ./code/angr-dev/claripy /home/angr/angr-dev/angr
RUN chown angr -R /home/angr/angr-dev/angr/angr
RUN chown angr -R /home/angr/angr-dev/claripy/claripy
cmd su - angr