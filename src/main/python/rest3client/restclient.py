
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
import base64
import requests
from collections import Iterable
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import copy
import time
import logging
logger = logging.getLogger(__name__)

logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.CRITICAL)

requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def redact(items, items_to_redact):
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


class RESTclient(object):

    cabundle = '/etc/ssl/certs/ca-certificates.crt'
    items_to_redact = [
        'Authorization',
        'Auth',
        'x-api-key',
        'Password',
        'password'
    ]

    def __init__(self, hostname, username=None, password=None, api_key=None, bearer_token=None, cabundle=None):
        """ class constructor
        """
        logger.debug('executing RESTclient constructor')
        self.hostname = hostname

        if not cabundle:
            cabundle = RESTclient.cabundle
        self.cabundle = cabundle if os.access(cabundle, os.R_OK) else False

        if username:
            self.username = username

        if password:
            self.password = password

        if api_key:
            self.api_key = api_key

        if bearer_token:
            self.bearer_token = bearer_token

    def get_headers(self, **kwargs):
        """ return headers to pass to requests method
        """
        headers = kwargs.get('headers', {})

        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        if hasattr(self, 'username') and hasattr(self, 'password'):
            basic = base64.b64encode(('{}:{}'.format(self.username, self.password)).encode())
            headers['Authorization'] = 'Basic {}'.format(basic).replace('b\'', '').replace('\'', '')

        if hasattr(self, 'api_key'):
            headers['x-api-key'] = self.api_key

        if hasattr(self, 'bearer_token'):
            headers['Authorization'] = 'Bearer {}'.format(self.bearer_token)

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

        arguments['address'] = 'https://{}{}'.format(self.hostname, endpoint)
        arguments.pop('raw_response', None)
        return arguments

    def log_request(self, function_name, arguments, noop):
        """ log request function name and redacted arguments
        """
        redacted_arguments = redact(arguments, self.items_to_redact)
        try:
            redacted_arguments = json.dumps(redacted_arguments, indent=2, sort_keys=True)
        except TypeError:
            pass

        logger.debug('\n{}: {} NOOP: {}\n{}'.format(
            function_name, arguments['address'], noop, redacted_arguments))

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

    def process_response(self, response, **kwargs):
        """ process request response
        """
        logger.debug('processing response')
        raw_response = kwargs.get('raw_response', False)
        if raw_response:
            logger.debug('returning raw response')
            return response

        if not response.ok:
            logger.debug('response was not OK')
            error_message = self.get_error_message(response)
            logger.error('{}: {}'.format(error_message, response.status_code))
            response.raise_for_status()

        logger.debug('response was OK')
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
            return self.process_response(response, **kwargs)

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

    request_handler = staticmethod(request_handler)
