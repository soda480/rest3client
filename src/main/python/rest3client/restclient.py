
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
import re
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
        'password',
        'JWT'
    ]

    def __init__(self, hostname, **kwargs):
        """ class constructor
        """
        logger.debug('executing RESTclient constructor')
        self.hostname = hostname
        self.session = requests.Session()

        cabundle = kwargs.get('cabundle', RESTclient.cabundle)
        self.cabundle = cabundle if os.access(cabundle, os.R_OK) else False

        self.username = kwargs.get('username')
        self.password = kwargs.get('password')

        self.api_key = kwargs.get('api_key')

        self.bearer_token = kwargs.get('bearer_token')

        self.jwt = kwargs.get('jwt')

        self.certfile = kwargs.get('certfile')
        self.certpass = kwargs.get('certpass')
        if self.certfile and self.certpass:
            ssl_adapter = SSLAdapter(certfile=self.certfile, certpass=self.certpass)
            self.session.mount(f'https://{self.hostname}', ssl_adapter)

        self.retries = kwargs.get('retries', [])
        self.decorate_retries()

    def get_headers(self, **kwargs):
        """ return headers to pass to requests method
        """
        headers = kwargs.get('headers', {})

        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        if self.username and self.password:
            basic = base64.b64encode((f'{self.username}:{self.password}').encode())
            headers['Authorization'] = f'Basic {basic}'.replace('b\'', '').replace('\'', '')

        if self.api_key:
            headers['x-api-key'] = self.api_key

        if self.bearer_token:
            headers['Authorization'] = f'Bearer {self.bearer_token}'

        if self.jwt:
            headers['Authorization'] = f'JWT {self.jwt}'

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
        redacted_arguments = self.redact(arguments)
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
            logger.debug(f'{error_message}: {response.status_code}')
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
            response = function(self, endpoint, **arguments)
            return self.get_response(response, **kwargs)

        return _request_handler

    @request_handler
    def post(self, endpoint, **kwargs):
        """ helper method to submit post requests
        """
        return self.session.request('post', kwargs.pop('address'), **kwargs)

    @request_handler
    def put(self, endpoint, **kwargs):
        """ helper method to submit put requests
        """
        return self.session.request('put', kwargs.pop('address'), **kwargs)

    @request_handler
    def get(self, endpoint, **kwargs):
        """ helper method to submit get requests
        """
        return self.session.request('get', kwargs.pop('address'), **kwargs)

    @request_handler
    def delete(self, endpoint, **kwargs):
        """ helper method to submit delete requests
        """
        return self.session.request('delete', kwargs.pop('address'), **kwargs)

    @request_handler
    def patch(self, endpoint, **kwargs):
        """ helper method to submit patch requests
        """
        return self.session.request('patch', kwargs.pop('address'), **kwargs)

    def get_retry_methods(self):
        """ return list of all retry_ methods found in self
        """
        return [
            item for item in dir(self) if callable(getattr(self, item)) and item.startswith('retry_')
        ]

    @staticmethod
    def add_retry_key_values(key_values, retry_text):
        """ add key value pairs parsed from retry_text to key_values
            method will first check if value is set as an environment variable
                ${method_name}_${argument}
        """
        method_name = key_values['retry_on_exception'].__name__
        for line in retry_text.split():
            if ':' in line:
                line_split = line.split(':')
                key = line_split[0]
                env_var = f'{method_name.upper()}_{key.upper()}'
                value = os.getenv(env_var, line_split[1])
                if not value:
                    raise ValueError(f"the retry argument '{key}' has no value and environment variable for '{env_var}' was not set")
                key_values[key] = int(value) if value.isnumeric() else value

    @staticmethod
    def get_retry_key_values(method, method_doc):
        """ return dictionary of retry key value pairs found in method doc
        """
        regex = r'^.*retry:(?P<retry_text>.*)$'
        match = re.match(regex, method_doc, re.DOTALL)
        if not match:
            return
        key_values = {
            'retry_on_exception': method
        }
        retry_text = match.group('retry_text').strip()
        RESTclient.add_retry_key_values(key_values, retry_text)
        return key_values

    def discover_retries(self):
        """ append all retry methods with their arguments discovered within self to the retries list in self
        """
        retry_methods = self.get_retry_methods()
        for retry_method in retry_methods:
            method = getattr(self, retry_method)
            method_doc = method.__doc__
            if not method_doc:
                continue
            retry_key_values = RESTclient.get_retry_key_values(method, method_doc)
            if not retry_key_values:
                continue
            logger.debug(f"discovered retry method '{retry_key_values['retry_on_exception'].__name__}'")
            self.retries.append(retry_key_values)

    def decorate_retries(self):
        """ decorate request methods with retry decorator where kwargs specified in retries list
            retry kwargs must conform to prescribed retry arguments, see: https://pypi.org/project/retrying/
        """
        self.discover_retries()
        logger.debug('adding retry decorators to all request methods')
        for retry_kwargs in self.retries:
            RESTclient.log_retry_kwargs(retry_kwargs)
            self.get = retry(**retry_kwargs)(self.get)
            self.post = retry(**retry_kwargs)(self.post)
            self.put = retry(**retry_kwargs)(self.put)
            self.delete = retry(**retry_kwargs)(self.delete)
            self.patch = retry(**retry_kwargs)(self.patch)

    @classmethod
    def redact(cls, items):
        """ return redacted copy of items dictionary
        """
        def _redact(items):
            """ redact private method
            """
            if isinstance(items, dict):
                for item_to_redact in cls.items_to_redact:
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

    @staticmethod
    def log_retry_kwargs(kwargs):
        """ log retry kwargs parameters
        """
        kwargs_copy = copy.deepcopy(kwargs)
        for key, value in kwargs.items():
            if callable(value):
                kwargs_copy[key] = value.__name__
        data = json.dumps(kwargs_copy, indent=2)
        logger.debug(f"\n{data}")

    request_handler = staticmethod(request_handler)
