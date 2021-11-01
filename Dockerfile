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
FROM python:3.9-slim AS build-image
ENV PYTHONDONTWRITEBYTECODE 1
ENV PATH="/home/python/.local/bin:${PATH}"
RUN groupadd -g 1000 python && useradd -u 1000 -d /home/python -m -g python python
WORKDIR /home/python/code
COPY . /home/python/code
RUN chown -R python:python /home/python/code/
USER python
RUN pip install --disable-pip-version-check pybuilder
RUN pyb install

FROM python:3.9-alpine
ENV PYTHONDONTWRITEBYTECODE 1
ENV PATH="/home/python/.local/bin:${PATH}"
RUN addgroup -g 1000 python && adduser -u 1000 -h /home/python -D -G python python
WORKDIR /home/python/
USER python
COPY --from=build-image /home/python/code/target/dist/rest3client-*/dist/rest3client-*.tar.gz .
RUN pip install --disable-pip-version-check rest3client-*.tar.gz