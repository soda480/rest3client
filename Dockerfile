#
# Copyright (c) 2020 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

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
