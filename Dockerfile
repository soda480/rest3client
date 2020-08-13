FROM python:3.6-alpine

ENV PYTHONDONTWRITEBYTECODE 1

WORKDIR /rest3client

COPY . /rest3client/

RUN pip install pybuilder==0.11.17
RUN pyb install_dependencies
RUN pyb clean
RUN pyb install

CMD echo 'DONE'
