FROM debian:latest

RUN apt-get -y -q update; \
    apt-get -y -q install nano python3 python3-pip git

RUN mkdir -p /opt/tools/

# Installing impacket
RUN apt-get -y -q install build-essential libffi-dev openssl rustc libssl-dev

RUN cd /opt/tools/ ;\
    git clone https://github.com/SecureAuthCorp/impacket ;\
    cd impacket ;\
    python3 -m pip install -r requirements.txt ;\
    python3 -m pip install .

# Installing tools
RUN python3 -m pip install rich requests

COPY ./ListAvailablePipesOnRemoteMachine/ /opt/tools/ListAvailablePipesOnRemoteMachine/
RUN echo 'ListAvailablePipesOnRemoteMachine' >> /root/.bash_history \
    && ln -s /opt/tools/ListAvailablePipesOnRemoteMachine/ListAvailablePipesOnRemoteMachine.py /bin/ListAvailablePipesOnRemoteMachine.py

COPY ./KnownCoerceMethodsFuzzer/ /opt/tools/KnownCoerceMethodsFuzzer/
RUN echo "KnownCoerceMethodsFuzzer.py -d COERCE.local -u 'Administrator' -p 'Admin123!' 192.168.1.27 192.168.1.47" >> /root/.bash_history \
    && ln -s /opt/tools/KnownCoerceMethodsFuzzer/KnownCoerceMethodsFuzzer.py /bin/KnownCoerceMethodsFuzzer.py

COPY ./OpnumBlindFuzzer/ /opt/tools/OpnumBlindFuzzer/
RUN echo 'OpnumBlindFuzzer' >> /root/.bash_history \
    && ln -s /opt/tools/OpnumBlindFuzzer/OpnumBlindFuzzer.py /bin/OpnumBlindFuzzer.py

WORKDIR /root/

CMD ["/bin/bash"]
