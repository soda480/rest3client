
# Copyright (c) 2020 Intel Corporation

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#      http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import json
import copy
import logging
import base64
import requests
from collections.abc import Iterable

from rest3client.ssladapter import SSLAdapter
from retrying import retry

logger = logging.getLogger(__name__)

logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.CRITICAL)


class RESTclient():
    """ class exposing abstracted requests-based http verb apis
    """

    cabundle = '/etc/ssl/certs/ca-certificates.crt'
    items_to_redact = [
        'Authorization',
        'Auth',
        'x-api-key',
        'Password',
        'password'
    ]

    def __init__(self, hostname, **kwargs):
        """ class constructor
        """
        logger.debug('executing RESTclient constructor')
        self.hostname = hostname

        cabundle = kwargs.get('cabundle')
        if not cabundle:
            cabundle = RESTclient.cabundle
        self.cabundle = cabundle if os.access(cabundle, os.R_OK) else False

        username = kwargs.get('username')
        if username:
            self.username = username

        password = kwargs.get('password')
        if password:
            self.password = password

        api_key = kwargs.get('api_key')
        if api_key:
            self.api_key = api_key

        bearer_token = kwargs.get('bearer_token')
        if bearer_token:
            self.bearer_token = bearer_token

        certfile = kwargs.get('certfile')
        certpass = kwargs.get('certpass')
        self.certfile = certfile
        self.ssl_adapter = None
        if certfile and certpass:
            self.ssl_adapter = SSLAdapter(certfile=certfile, certpass=certpass)

        retries = kwargs.get('retries')
        if retries:
            self.decorate_retry(retries)
            self.retries = retries

    def get_headers(self, **kwargs):
        """ return headers to pass to requests method
        """
        headers = kwargs.get('headers', {})

        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        if hasattr(self, 'username') and hasattr(self, 'password'):
            basic = base64.b64encode((f'{self.username}:{self.password}').encode())
            headers['Authorization'] = f'Basic {basic}'.replace('b\'', '').replace('\'', '')

        if hasattr(self, 'api_key'):
            headers['x-api-key'] = self.api_key

        if hasattr(self, 'bearer_token'):
            headers['Authorization'] = f'Bearer {self.bearer_token}'

        return headers

    def get_arguments(self, endpoint, kwargs):
        """ return key word arguments to pass to requests method
        """
        arguments = copy.deepcopy(kwargs)

        headers = self.get_headers(**kwargs)
        if 'headers' not in arguments:
            arguments['headers'] = headers
        else:
            arguments['headers'].update(headers)

        if 'verify' not in arguments or arguments.get('verify') is None:
            arguments['verify'] = self.cabundle

        if endpoint.startswith('http'):
            arguments['address'] = endpoint
        else:
            arguments['address'] = f'https://{self.hostname}{endpoint}'
        arguments.pop('raw_response', None)
        return arguments

    def log_request(self, function_name, arguments, noop):
        """ log request function name and redacted arguments
        """
        redacted_arguments = RESTclient.redact(arguments, self.items_to_redact)
        try:
            redacted_arguments = json.dumps(redacted_arguments, indent=2, sort_keys=True)
        except TypeError:
            pass

        cert = f'\nCERT: {self.certfile}' if self.certfile else ''
        logger.debug(f"\n{function_name}: {arguments['address']} NOOP: {noop}\n{redacted_arguments}{cert}")

    def get_error_message(self, response):
        """ return error message from response
        """
        logger.debug('getting error message from response')
        try:
            response_json = response.json()
            logger.debug('returning error from response json')
            return response_json

        except ValueError:
            logger.debug('returning error from response text')
            return response.text

    def get_response(self, response, **kwargs):
        """ return request response
        """
        logger.debug('processing response')

        if not response.ok:
            logger.debug('response was not OK')
            error_message = self.get_error_message(response)
            logger.error(f'{error_message}: {response.status_code}')
            response.raise_for_status()

        logger.debug('response was OK')

        raw_response = kwargs.get('raw_response', False)
        if raw_response:
            logger.debug('returning raw response')
            return response

        try:
            response_json = response.json()
            logger.debug('returning response json')
            return response_json

        except ValueError:
            logger.debug('returning response text')
            return response.text

    def request_handler(function):
        """ decorator to process arguments and response for request method
        """
        def _request_handler(self, endpoint, **kwargs):
            """ decorator method to prepare and handle requests and responses
            """
            noop = kwargs.pop('noop', False)
            arguments = self.get_arguments(endpoint, kwargs)
            self.log_request(function.__name__.upper(), arguments, noop)
            if noop:
                return
            if self.ssl_adapter:
                with requests.Session() as session:
                    session.mount(f'https://{self.hostname}', self.ssl_adapter)
                    response = session.request(function.__name__, arguments.pop('address'), **arguments)
            else:
                response = function(self, endpoint, **arguments)
            return self.get_response(response, **kwargs)

        return _request_handler

    @request_handler
    def post(self, endpoint, **kwargs):
        """ helper method to submit post requests
        """
        return requests.post(kwargs.pop('address'), **kwargs)

    @request_handler
    def put(self, endpoint, **kwargs):
        """ helper method to submit put requests
        """
        return requests.put(kwargs.pop('address'), **kwargs)

    @request_handler
    def get(self, endpoint, **kwargs):
        """ helper method to submit get requests
        """
        return requests.get(kwargs.pop('address'), **kwargs)

    @request_handler
    def delete(self, endpoint, **kwargs):
        """ helper method to submit delete requests
        """
        return requests.delete(kwargs.pop('address'), **kwargs)

    @request_handler
    def patch(self, endpoint, **kwargs):
        """ helper method to submit patch requests
        """
        return requests.patch(kwargs.pop('address'), **kwargs)

    def decorate_retry(self, retries):
        """ decorate request methods with retry decorator where kwargs specified in retries list
            retry kwargs must conform to prescribed retry arguments, see: https://pypi.org/project/retrying/
        """
        logger.debug('decorating request methods with retry')
        for retry_kwargs in retries:
            RESTclient.log_retry_kwargs(retry_kwargs)
            self.get = retry(**retry_kwargs)(self.get)
            self.post = retry(**retry_kwargs)(self.post)
            self.put = retry(**retry_kwargs)(self.put)
            self.delete = retry(**retry_kwargs)(self.delete)
            self.patch = retry(**retry_kwargs)(self.patch)

    @classmethod
    def redact(cls, items, items_to_redact):
        """ return redacted copy of items dictionary
        """
        def _redact(items):
            """ redact private method
            """
            if isinstance(items, dict):
                for item_to_redact in items_to_redact:
                    if item_to_redact in items:
                        items[item_to_redact] = '[REDACTED]'
                for item in items.values():
                    _redact(item)
            elif isinstance(items, Iterable) and not isinstance(items, str):
                for item in items:
                    _redact(item)

        scrubbed = copy.deepcopy(items)
        if 'address' in scrubbed:
            del scrubbed['address']
        for value in scrubbed.values():
            _redact(value)
        return scrubbed

    @classmethod
    def log_retry_kwargs(cls, kwargs):
        """ log retry kwargs parameters
        """
        for key, value in kwargs.items():
            if callable(value):
                value = value.__name__
            logger.debug(f'{key}={value}')

    request_handler = staticmethod(request_handler)
