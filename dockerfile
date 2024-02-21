FROM python:3.8

WORKDIR /karton/
RUN apt-get update
RUN apt install -y git
RUN git clone https://github.com/polyswarm/polyunite
RUN pip install ./polyunite
RUN pip install polyswarm_api karton-core
COPY karton/scanner scanner
CMD [ "python", "-m", "scanner" ]