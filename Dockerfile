FROM python:3.6.5-slim

ENV PYTHONDONTWRITEBYTECODE 1

RUN mkdir /rest3client

COPY . /rest3client/

WORKDIR /rest3client

RUN apt-get update
RUN apt-get install -y git gcc libssl-dev
RUN pip install pybuilder==0.11.17
RUN pyb install_dependencies
RUN pyb install

WORKDIR /rest3client
CMD echo 'DONE'
