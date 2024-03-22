
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

import unittest
from mock import patch
from mock import mock_open
from mock import call
from mock import Mock
from rest3client import RESTcli
from argparse import Namespace
import sys


class TestRESTcli(unittest.TestCase):

    def setUp(self):
        """
        """
        pass

    def tearDown(self):
        """
        """
        pass

    @patch('rest3client.RESTcli.execute')
    def test__init__Should_CallExpected_When_Called(self, execute_patch, *patches):
        RESTcli()
        execute_patch.assert_called_once_with()

    @patch('rest3client.RESTcli.process_response')
    @patch('rest3client.RESTcli.get_attributes')
    @patch('rest3client.RESTcli.execute_request')
    @patch('rest3client.RESTcli.get_client')
    @patch('rest3client.restcli.logging')
    @patch('rest3client.RESTcli.get_parser')
    def test__execute_Should_ConfigLogging_When_Debug(self, get_parser_patch, logging_patch, *patches):
        parser_mock = Mock()
        parser_mock.parse_args.return_value = Namespace(debug=True)
        get_parser_patch.return_value = parser_mock
        client = RESTcli(execute=False)
        client.execute()
        logging_patch.basicConfig.assert_called()

    @patch('rest3client.RESTcli.process_response')
    @patch('rest3client.RESTcli.get_attributes')
    @patch('rest3client.RESTcli.execute_request')
    @patch('rest3client.RESTcli.get_client')
    @patch('rest3client.restcli.logging')
    @patch('rest3client.RESTcli.get_parser')
    def test__execute_Should_ConfigLogging_When_NoDebug(self, get_parser_patch, logging_patch, *patches):
        parser_mock = Mock()
        parser_mock.parse_args.return_value = Namespace(debug=False)
        get_parser_patch.return_value = parser_mock
        client = RESTcli(execute=False)
        client.execute()
        logging_patch.basicConfig.assert_not_called()

    def test__get_parser_Should_CallExpected_When_Called(self, *patches):
        client = RESTcli(execute=False)
        client.get_parser()
        # nothing to assert

    @patch('rest3client.restcli.getenv')
    def test__get_authentication_Should_ReturnExpected_When_AuthKeys(self, getenv_patch, *patches):
        getenv_patch.side_effect = [
            None,
            None,
            None,
            None,
            '--certfile--',
            '--certpass--',
            None
        ]
        client = RESTcli(execute=False)
        result = client.get_authentication()
        expected_result = {
            'certfile': '--certfile--',
            'certpass': '--certpass--'
        }
        self.assertEqual(result, expected_result)

    @patch('rest3client.restcli.getenv', return_value=None)
    def test__get_authentication_Should_ReturnExpected_When_NoAuthKeys(self, *patches):
        client = RESTcli(execute=False)
        result = client.get_authentication()
        expected_result = {}
        self.assertEqual(result, expected_result)

    @patch('rest3client.RESTcli.get_authentication')
    @patch('rest3client.restcli.RESTclient')
    def test__get_client_Should_ReturnExpected_When_Called(self, restclient_patch, get_authentication_patch, *patches):
        get_authentication_patch.return_value = {
            'arg1': 'val1',
            'arg2': 'val2'
        }
        client = RESTcli(execute=False)
        client.args = Namespace(address='--address--')
        result = client.get_client()
        restclient_patch.assert_called_once_with('--address--', arg1='val1', arg2='val2')
        self.assertEqual(result, restclient_patch.return_value)

    def test__get_attributes_Should_ReturnExpected_When_Attributes(self, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(attributes='attr1, attr2,attr3,    attr4')
        result = client.get_attributes()
        expected_result = ['attr1', 'attr2', 'attr3', 'attr4']
        self.assertEqual(result, expected_result)

    def test__get_attributes_Should_ReturnExpected_When_NoAttributes(self, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(attributes='')
        result = client.get_attributes()
        self.assertIsNone(result)

    def test__get_arguments_Should_ReturnExpected_When_Values(self, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(json_data="{'j1':'v1'}", headers_data="{'h1':'v1'}", raw_response=True)
        result = client.get_arguments()
        expected_result = {
            'json': {'j1': 'v1'},
            'headers': {'h1': 'v1'},
            'raw_response': True
        }
        self.assertEqual(result, expected_result)

    def test__get_arguments_Should_ReturnExpected_When_NoValues(self, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(json_data=None, headers_data=None, raw_response=None)
        result = client.get_arguments()
        expected_result = {}
        self.assertEqual(result, expected_result)

    @patch('rest3client.RESTcli.get_arguments', return_value={})
    def test__execute_request_Should_CallAndReturnExpected_When_Get(self, get_arguments_patch, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(method='GET', endpoint='/endpoint')
        rest_client_mock = Mock()
        result = client.execute_request(rest_client_mock)
        rest_client_mock.get.assert_called_once_with('/endpoint')
        self.assertEqual(result, rest_client_mock.get.return_value)

    @patch('rest3client.RESTcli.get_arguments', return_value={})
    def test__execute_request_Should_CallAndReturnExpected_When_Post(self, get_arguments_patch, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(method='POST', endpoint='/endpoint')
        rest_client_mock = Mock()
        result = client.execute_request(rest_client_mock)
        rest_client_mock.post.assert_called_once_with('/endpoint')
        self.assertEqual(result, rest_client_mock.post.return_value)

    @patch('rest3client.RESTcli.get_arguments', return_value={})
    def test__execute_request_Should_CallAndReturnExpected_When_Put(self, get_arguments_patch, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(method='PUT', endpoint='/endpoint')
        rest_client_mock = Mock()
        result = client.execute_request(rest_client_mock)
        rest_client_mock.put.assert_called_once_with('/endpoint')
        self.assertEqual(result, rest_client_mock.put.return_value)

    @patch('rest3client.RESTcli.get_arguments', return_value={})
    def test__execute_request_Should_CallAndReturnExpected_When_Patch(self, get_arguments_patch, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(method='PATCH', endpoint='/endpoint')
        rest_client_mock = Mock()
        result = client.execute_request(rest_client_mock)
        rest_client_mock.patch.assert_called_once_with('/endpoint')
        self.assertEqual(result, rest_client_mock.patch.return_value)

    @patch('rest3client.RESTcli.get_arguments', return_value={})
    def test__execute_request_Should_CallAndReturnExpected_When_Delete(self, get_arguments_patch, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(method='DELETE', endpoint='/endpoint')
        rest_client_mock = Mock()
        result = client.execute_request(rest_client_mock)
        rest_client_mock.delete.assert_called_once_with('/endpoint')
        self.assertEqual(result, rest_client_mock.delete.return_value)

    def test__filter_response_Should_ReturnResponse_When_NoAttributes(self, *patches):
        client = RESTcli(execute=False)
        result = client.filter_response('--response--', None)
        expected_result = '--response--'
        self.assertEqual(result, expected_result)

    def test__filter_response_Should_ReturnResponse_When_AttributesAndResponseIsDict(self, *patches):
        client = RESTcli(execute=False)
        response = {
            'a1': 'v1',
            'a2': 'v2',
            'a3': 'v3',
            'a4': 'v4'
        }
        attributes = ['a2', 'a4', 'a5']
        result = client.filter_response(response, attributes)
        expected_result = {
            'a2': 'v2',
            'a4': 'v4'
        }
        self.assertEqual(result, expected_result)

    def test__filter_response_Should_ReturnResponse_When_RegExAttributesAndResponseIsDict(self, *patches):
        client = RESTcli(execute=False)
        response = {
            'a1': 'v1',
            'a2': 'v2',
            'a3': 'v3',
            'a4': 'v4',
            'b1': 'vb1',
            'c1': 'vc1'
        }
        attributes = ['a.*', 'a4', 'c1']
        result = client.filter_response(response, attributes)
        expected_result = {
            'a1': 'v1',
            'a2': 'v2',
            'a3': 'v3',
            'a4': 'v4',
            'c1': 'vc1'
        }
        self.assertEqual(result, expected_result)

    def test__filter_response_Should_ReturnResponse_When_AttributesAndResponseIsList(self, *patches):
        client = RESTcli(execute=False)
        response = [
            {
                'a1': 'v1',
                'a2': 'v2',
                'a3': 'v3',
                'a4': 'v4'
            }, {
                'a1': 'v1',
                'a2': 'v2',
                'a3': 'v3',
                'a4': 'v4'
            }
        ]
        attributes = ['a2']
        result = client.filter_response(response, attributes)
        expected_result = [
            {
                'a2': 'v2'
            }, {
                'a2': 'v2'
            }
        ]
        self.assertEqual(result, expected_result)

    def test__filter_response_Should_ReturnResponse_When_AttributesAndResponseIsStr(self, *patches):
        client = RESTcli(execute=False)
        attributes = ['a2']
        result = client.filter_response('--response--', attributes)
        expected_result = '--response--'
        self.assertEqual(result, expected_result)

    @patch('rest3client.restcli.json.dumps')
    @patch('rest3client.RESTcli.filter_response')
    def test__process_response_Should_CallExpected_When_AttributesRawResponse(self, filter_response_patch, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(raw_response=True, key=None)
        attributes = ['a2']
        response_mock = Mock()
        response_mock.headers = {'h1': 'v1'}
        client.process_response(response_mock, attributes)

    @patch('rest3client.restcli.json.dumps')
    @patch('rest3client.RESTcli.filter_response')
    def test__process_response_Should_CallExpected_When_AttributesNoRawResponse(self, filter_response_patch, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(raw_response=None, key=None)
        attributes = ['a2']
        client.process_response('--response--', attributes)

    @patch('rest3client.restcli.json.dumps')
    @patch('rest3client.RESTcli.filter_response')
    def test__process_response_Should_CallExpected_When_NoAttributesRawResponse(self, filter_response_patch, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(raw_response=True)
        response_mock = Mock()
        response_mock.status_code = 202
        response_mock.headers = {}
        client.process_response(response_mock, None)

    @patch('rest3client.restcli.json.dumps')
    @patch('rest3client.RESTcli.filter_response')
    def test__process_response_Should_CallExpected_When_KeyAttributesRawResponse(self, filter_response_patch, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace(raw_response=True, key=True)
        headers = {'key': 'value'}
        response_mock = Mock()
        response_mock.headers = headers
        filter_response_patch.return_value = headers
        attributes = ['a2']
        client.process_response(response_mock, attributes)

    def test__process_response_Should_CallExpected_When_NoAttributesNoResponse(self, *patches):
        client = RESTcli(execute=False)
        client.args = Namespace()
        client.process_response(None, None)
