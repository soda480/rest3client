FROM python:3.6-alpine AS build-image

ENV PYTHONDONTWRITEBYTECODE 1

WORKDIR /rest3client

COPY . /rest3client/

RUN pip install pybuilder==0.11.17
RUN pyb install_dependencies
RUN pyb install


FROM python:3.6-alpine

ENV PYTHONDONTWRITEBYTECODE 1

WORKDIR /opt/rest3client

COPY --from=build-image /rest3client/target/dist/rest3client-*/dist/rest3client-*.tar.gz /opt/rest3client

RUN pip install rest3client-*.tar.gz

CMD echo 'DONE'
