
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
from functools import wraps

from rest3client.ssladapter import SSLAdapter
from retrying import retry

logger = logging.getLogger(__name__)

logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.CRITICAL)


class RedactingFormatter(logging.Formatter):

    def __init__(self, orig_formatter, secrets=None):
        self.orig_formatter = orig_formatter
        self._secrets = secrets

    def format(self, record):
        msg = self.orig_formatter.format(record)
        if self._secrets:
            for secret in self._secrets:
                if secret in msg:
                    msg = msg.replace(secret, "[REDACTED]")
        return msg

    def __getattr__(self, attr):
        return getattr(self.orig_formatter, attr)


class RESTclient():
    """ class exposing abstracted requests-based http verb apis
    """

    cabundle = '/etc/ssl/certs/ca-certificates.crt'

    def __init__(self, hostname, **kwargs):
        """ class constructor
        """
        logger.debug('executing RESTclient constructor')
        self.hostname = hostname
        self.session = requests.Session()

        self.cabundle = RESTclient.get_cabundle(kwargs.get('cabundle'))

        self.username = kwargs.get('username')
        self.password = kwargs.get('password')

        self.api_key = kwargs.get('api_key')
        self.apikey = kwargs.get('apikey')

        self.bearer_token = kwargs.get('bearer_token')

        self.token = kwargs.get('token')

        self.jwt = kwargs.get('jwt')

        self.basic_token = kwargs.get('basic_token')

        self.certfile = kwargs.get('certfile')
        self.certkey = kwargs.get('certkey')
        self.certpass = kwargs.get('certpass')
        if self.certfile and (self.certkey or self.certpass):
            ssl_adapter = SSLAdapter(certfile=self.certfile, certkey=self.certkey, certpass=self.certpass)
            self.session.mount(f'https://{self.hostname}', ssl_adapter)

        self.retries = kwargs.get('retries', [])
        self.decorate_retries()

        items_to_redact = [
            self.password,
            self.api_key,
            self.apikey,
            self.bearer_token,
            self.token,
            self.jwt,
            self.certpass
        ]
        if self.username and self.password and not self.basic_token:
            self.basic = base64.b64encode((f'{self.username}:{self.password}').encode())
            self.basic = f'{self.basic}'.replace('b\'', '').replace('\'', '')
            items_to_redact.append(self.basic)

        if self.basic_token:
            # basic token takes precendence over username/password
            items_to_redact.append(self.basic_token)

        items_to_be_redacted = [item for item in items_to_redact if item]
        for handler in logger.root.handlers:
            handler.setFormatter(RedactingFormatter(handler.formatter, secrets=items_to_be_redacted))

    def get_headers(self, **kwargs):
        """ return headers to pass to requests method
        """
        headers = kwargs.get('headers', {})

        if 'files' not in kwargs and 'Content-Type' not in headers:
            # do not set Content-Type when files are being posted
            headers['Content-Type'] = 'application/json'

        if self.username and self.password:
            headers['Authorization'] = f'Basic {self.basic}'

        if self.api_key:
            headers['x-api-key'] = self.api_key

        if self.apikey:
            headers['apikey'] = self.apikey

        if self.bearer_token:
            headers['Authorization'] = f'Bearer {self.bearer_token}'

        if self.token:
            headers['Authorization'] = self.token

        if self.jwt:
            headers['Authorization'] = f'JWT {self.jwt}'

        if self.basic_token:
            headers['Authorization'] = f'Basic {self.basic_token}'

        return headers

    def get_arguments(self, endpoint, kwargs):
        """ update kwargs with required values to pass to requests method
        """
        headers = self.get_headers(**kwargs)
        if 'headers' not in kwargs:
            kwargs['headers'] = headers
        else:
            kwargs['headers'].update(headers)

        if 'verify' not in kwargs or kwargs.get('verify') is None:
            kwargs['verify'] = self.cabundle

        if endpoint.startswith('http'):
            kwargs['address'] = endpoint
        else:
            kwargs['address'] = f'https://{self.hostname}{endpoint}'

    def log_request(self, function_name, arguments, noop):
        """ log request function name and redacted arguments
        """
        redacted_arguments = json.dumps(arguments, indent=2, sort_keys=True, default=str)
        cert = f'\nCERT: {self.certfile}' if self.certfile else ''
        if function_name.startswith('_'):
            function_name = function_name[1:]
        logger.debug(f"\n{function_name}: {arguments['address']}   NOOP: {noop}\n{redacted_arguments}{cert}")

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
            logger.debug('response was NOT OK')
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
        @wraps(function)
        def _request_handler(self, endpoint, **kwargs):
            """ decorator method to prepare and handle requests and responses
            """
            noop = kwargs.pop('noop', False)
            raw_response = kwargs.pop('raw_response', None)
            self.get_arguments(endpoint, kwargs)
            self.log_request(function.__name__.upper(), kwargs, noop)
            if noop:
                return
            response = function(self, endpoint, **kwargs)
            kwargs['raw_response'] = raw_response
            return self.get_response(response, **kwargs)
        return _request_handler

    def _get_endpoint_from_url(self, url):
        """ return endpoint from url
        """
        return url.replace(f'https://{self.hostname}', '')

    def _get_next_endpoint(self, url):
        """ return next endpoint
        """
        if not url:
            logger.debug('link header is empty')
            return
        endpoint = self._get_endpoint_from_url(url)
        logger.debug(f'next endpoint is: {endpoint}')
        return endpoint

    def _page(self, function, endpoint, **kwargs):
        """ return generator that yields pages from endpoint
        """
        while True:
            response = function(self, endpoint, raw_response=True, **kwargs)
            yield response.json()
            endpoint = self._get_next_endpoint(response.links.get('next', {}).get('url'))
            if not endpoint:
                logger.debug('no more pages')
                break

    def _all(self, function, endpoint, **kwargs):
        """ return all pages from endpoint
        """
        logger.debug(f'get items from: {endpoint}')
        items = []
        while True:
            url = None
            response = function(self, endpoint, raw_response=True, **kwargs)
            if response:
                data = response.json()
                if isinstance(data, list):
                    items.extend(response.json())
                else:
                    items.append(data)
                url = response.links.get('next', {}).get('url')
            endpoint = self._get_next_endpoint(url)
            if not endpoint:
                logger.debug('no more pages to retrieve')
                break
        return items

    def page_handler(function):
        """ decorator to process paging
        """
        @wraps(function)
        def _page_handler(self, endpoint, **kwargs):
            """ inner decorator to process paging
            """
            private_method = getattr(RESTclient, f'_{function.__name__}', None)
            if not private_method:
                raise ValueError('page_handler must decorate a method that has an associated private method')
            directive = kwargs.pop(f'_{function.__name__}', None)
            if directive == 'all':
                attributes = kwargs.pop('_attributes', None)
                items = self._all(private_method, endpoint, **kwargs)
                return RESTclient.match_keys(items, attributes)
            elif directive == 'page':
                return self._page(private_method, endpoint, **kwargs)
            else:
                return private_method(self, endpoint, **kwargs)
        return _page_handler

    @request_handler
    def _get(self, endpoint, **kwargs):
        """ helper method to submit get requests
        """
        return self.session.request('get', kwargs.pop('address'), **kwargs)

    @request_handler
    def _post(self, endpoint, **kwargs):
        """ helper method to submit post requests
        """
        return self.session.request('post', kwargs.pop('address'), **kwargs)

    @page_handler
    def get(self, endpoint, **kwargs):
        """ helper method to handle paged get requests
        """
        pass  # pragma: no cover

    @page_handler
    def post(self, endpoint, **kwargs):
        """ helper method to handle paged post requests
        """
        pass  # pragma: no cover

    @request_handler
    def put(self, endpoint, **kwargs):
        """ helper method to submit put requests
        """
        return self.session.request('put', kwargs.pop('address'), **kwargs)

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

    @request_handler
    def head(self, endpoint, **kwargs):
        """ helper method to submit head requests
        """
        return self.session.request('head', kwargs.pop('address'), **kwargs)

    def get_retry_methods(self):
        """ return list of retry_ methods found in self
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
                    raise ValueError(f"the retry argument '{key}' has no value and environment variable '{env_var}' was not set")
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
        """ append retry methods and arguments discovered within self to self.retries
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
        """ decorate request methods with retry decorator specefied in self.retries
            self.retries arguments must adhere to retry arguments, see: https://pypi.org/project/retrying/
        """
        self.discover_retries()
        for retry_kwargs in self.retries:
            loggable_retry_kwargs = RESTclient.get_loggable_kwargs(retry_kwargs)
            logger.debug(f'adding retry decorator to all request methods:\n{loggable_retry_kwargs}')
            self.get = retry(**retry_kwargs)(self.get)
            self.post = retry(**retry_kwargs)(self.post)
            self.put = retry(**retry_kwargs)(self.put)
            self.delete = retry(**retry_kwargs)(self.delete)
            self.patch = retry(**retry_kwargs)(self.patch)

    @staticmethod
    def get_loggable_kwargs(kwargs):
        """ return copy of kwargs that can be logged (serializable)
        """
        kwargs_copy = copy.deepcopy(kwargs)
        for key, value in kwargs.items():
            if callable(value):
                kwargs_copy[key] = value.__name__
        return json.dumps(kwargs_copy, indent=2)

    @staticmethod
    def get_cabundle(cabundle):
        """ return value for cabundle
        """
        if not cabundle:
            cabundle = os.getenv('REQUESTS_CA_BUNDLE', RESTclient.cabundle)

        if not os.access(cabundle, os.R_OK):
            logger.warn(f'cabundle "{cabundle}" is not accessible')
            cabundle = False

        return cabundle

    @staticmethod
    def match_keys(items, attributes):
        """ return list of items with matching keys from list of attributes
        """
        if not attributes:
            return items
        matched_items = []
        for item in items:
            matched_items.append({
                key: item[key] for key in attributes if key in item
            })
        return matched_items

    page_handler = staticmethod(page_handler)
    request_handler = staticmethod(request_handler)
