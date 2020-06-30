FROM angr_predict:v0.0.1

RUN su - angr -c "mkdir /home/angr/test && mkdir /home/angr/model"
COPY ./code/angr-dev/angr/ /home/angr/angr-dev/angr/angr/
COPY ./code/angr-dev/claripy/ /home/angr/angr-dev/claripy/claripy/
COPY ./code/test/ /home/angr/test/
COPY ./code/model/ /home/angr/model/
RUN chown angr -R /home/angr/angr-dev/angr/angr
RUN chown angr -R /home/angr/angr-dev/claripy/claripy
RUN chown angr -R /home/angr/test
RUN chown angr -R /home/angr/model
cmd su - angr