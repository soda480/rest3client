
import re
import sys
import json
import logging
import argparse
import requests
import urllib3
from os import getenv
from collections.abc import Iterable
from rest3client import RESTclient

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_attrs(data, attrs):
    """ return list of attributes and their values from data where
        data can be a dict or a list of dicts
    """
    if not attrs:
        return data
    if isinstance(data, (dict, requests.structures.CaseInsensitiveDict)):
        result = {}
        for attr in attrs:
            value = get_attr(data, attr)
            if value is not None:
                result[attr] = value
        return result
    if isinstance(data, Iterable) and not isinstance(data, str):
        result = []
        for item in data:
            result.append(get_attrs(item, attrs))
        return result
    # return data if it is not a dict or non-str iterable
    return data


def get_attr(data, attr):
    """ get attribute denoted by attr from data dict
        attr can be a dot annotated attribute
    """
    if not isinstance(data, dict):
        return
    if '.' in attr:
        attrs = attr.split('.')
        if attrs[0] in data:
            return get_attr(data[attrs[0]], '.'.join(attrs[1:]))
    else:
        return data.get(attr)


class RESTcli():
    """ class defining CLI for RESTclient
    """

    auth_keys = [
        'USERNAME',
        'PASSWORD',
        'API_KEY',
        'BEARER_TOKEN',
        'CERTFILE',
        'CERTPASS',
        'JWT',
        'BASIC_TOKEN'
    ]

    def __init__(self, execute=True):
        """ RESTcli constructor
        """
        if execute:
            self.execute()

    def execute(self):
        """ execute CLI tasks
        """
        parser = self.get_parser()
        self.args = parser.parse_args()
        self.configure_logging()
        client = self.get_client()
        response = self.execute_request(client, skip_ssl=parser.skip_ssl)
        attributes = self.get_attributes()
        self.process_response(response, attributes)

    def get_parser(self):
        """ return argument parser
        """
        parser = argparse.ArgumentParser(
            description='A CLI for rest3client')
        parser.add_argument(
            'method',
            metavar='method',
            type=str,
            choices=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
            help='HTTP request method')
        parser.add_argument(
            'endpoint',
            metavar='endpoint',
            type=str,
            help='REST API endpoint')
        parser.add_argument(
            '--address',
            dest='address',
            type=str,
            default=getenv('R3C_ADDRESS'),
            required=False,
            help='HTTP request web address')
        parser.add_argument(
            '--json',
            dest='json_data',
            type=str,
            required=False,
            help='string representing JSON serializable object to send to HTTP request method')
        parser.add_argument(
            '--headers',
            dest='headers_data',
            type=str,
            required=False,
            help='string representing headers dictionary to send to HTTP request method')
        parser.add_argument(
            '--attributes',
            dest='attributes',
            type=str,
            required=False,
            help='attributes to filter from response')
        parser.add_argument(
            '--debug',
            dest='debug',
            action='store_true',
            help='display debug messages to stdout')
        parser.add_argument(
            '--index',
            dest='index',
            default=-1,
            type=int,
            required=False,
            help='return the item at the provided index - only valid if response is a list')
        parser.add_argument(
            '--skip-ssl',
            dest='skip_ssl',
            action='store_true',
            help='skip SSL certificate validation')
        return parser

    def configure_logging(self):
        """ configure logging
        """
        if self.args.debug:
            logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.ERROR)

    def get_authentication(self):
        """ return sanitized dictionary consisting of any R3C auth environment variables
        """
        auth = {}
        for auth_key in self.auth_keys:
            auth_key_value = getenv(f'R3C_{auth_key}')
            if auth_key_value:
                auth[auth_key.lower()] = auth_key_value
        return auth

    def get_client(self):
        """ return instance of RESTclient
        """
        return RESTclient(self.args.address, **self.get_authentication())

    def get_attributes(self):
        """ return comma-delimited string of attributes as list
        """
        if self.args.attributes:
            return [attribute.strip() for attribute in self.args.attributes.split(',')]

    def get_arguments(self):
        """ return dictionary of arguments to pass request method
        """
        arguments = {}
        if self.args.json_data:
            json_data = self.args.json_data.replace("'", '"')
            try:
                arguments['json'] = json.loads(json_data)
            except json.JSONDecodeError:
                raise ValueError('--json value is not a valid JSON object')
        if self.args.headers_data:
            headers_data = self.args.headers_data.replace("'", '"')
            try:
                arguments['headers'] = json.loads(headers_data)
            except json.JSONDecodeError:
                raise ValueError('--headers value is not a valid JSON object')
        else:
            headers_data = getenv('R3C_HEADERS')
            if headers_data:
                logger.debug('using headers from R3C_HEADERS environment variable')
                headers_data = headers_data.replace("'", '"')
                try:
                    arguments['headers'] = json.loads(headers_data)
                except json.JSONDecodeError:
                    raise ValueError('R3C_HEADERS environment variable is not a valid JSON object')
        return arguments

    def execute_request(self, client, skip_ssl=False):
        """ execute HTTP request method
        """
        arguments = self.get_arguments()
        if skip_ssl:
            arguments['verify'] = False
        if self.args.method == 'POST':
            response = client.post(self.args.endpoint, **arguments)
        elif self.args.method == 'PUT':
            response = client.put(self.args.endpoint, **arguments)
        elif self.args.method == 'PATCH':
            response = client.patch(self.args.endpoint, **arguments)
        elif self.args.method == 'DELETE':
            response = client.delete(self.args.endpoint, **arguments)
        else:
            response = client.get(self.args.endpoint, **arguments)
        return response

    def process_response(self, response, attributes):
        """ process HTTP request response
        """
        result = get_attrs(response, attributes)
        if result:
            if self.args.index >= 0 and isinstance(result, list):
                if len(result) > self.args.index:
                    result = result[self.args.index]
                else:
                    raise ValueError(f'length of result is {len(result)} less than provided index {self.args.index}')
            print(json.dumps(result, indent=3))
