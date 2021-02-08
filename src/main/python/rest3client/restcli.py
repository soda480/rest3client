
import re
import sys
import json
import logging
import argparse
import requests
from os import getenv
from collections.abc import Iterable

from rest3client import RESTclient

logger = logging.getLogger(__name__)


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
        'JWT'
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
        response = self.execute_request(client)
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
            help='attributes to filter from response - if used with --raw will filter from headers otherwise will filter from JSON response')
        parser.add_argument(
            '--debug',
            dest='debug',
            action='store_true',
            help='display debug messages to stdout')
        parser.add_argument(
            '--raw',
            dest='raw_response',
            action='store_true',
            help='return raw response from HTTP request method')
        parser.add_argument(
            '--key',
            dest='key',
            action='store_true',
            help='return key value in response - only if response is a dictionary containing a single key value')
        return parser

    def configure_logging(self):
        """ configure logging
        """
        if self.args.debug:
            logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

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
            arguments['json'] = json.loads(json_data)
        if self.args.headers_data:
            headers_data = self.args.headers_data.replace("'", '"')
            arguments['headers'] = json.loads(headers_data)
        if self.args.raw_response:
            arguments['raw_response'] = True
        # logger.debug(f'arguments parsed from cli are:\n{arguments}')
        return arguments

    def execute_request(self, client):
        """ execute HTTP request method
        """
        arguments = self.get_arguments()
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

    def filter_response(self, response, attributes):
        """ filter response containing specified attributes
        """
        if not attributes:
            return response

        if isinstance(response, (dict, requests.structures.CaseInsensitiveDict)):
            filtered = {}
            for key in response:
                for attribute in attributes:
                    if re.match(attribute, key):
                        if key not in filtered:
                            filtered[key] = response[key]

        elif isinstance(response, Iterable) and not isinstance(response, str):
            filtered = []
            for item in response:
                filtered.append(self.filter_response(item, attributes))

        else:
            filtered = response

        return filtered

    def process_response(self, response, attributes):
        """ process HTTP request response
        """
        if attributes:
            if self.args.raw_response:
                result = self.filter_response(response.headers, attributes)
            else:
                result = self.filter_response(response, attributes)
        else:
            result = response

        if result:
            if self.args.raw_response and not attributes:
                print(f'status_code: {result.status_code}')
                print(f'url: {result.url}')
                print('headers:')
                print(json.dumps(dict(result.headers), indent=2))
                print('json:')
                print(json.dumps(result.json(), indent=2))
            else:
                if self.args.key and len(result) == 1 and isinstance(result, dict):
                    print(list(result.values())[0])
                else:
                    print(json.dumps(result, indent=2))
