
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

from rest3client.ssladapter import SSLAdapter

import logging
logger = logging.getLogger(__name__)


class TestSSLAdapter(unittest.TestCase):

    def setUp(self):
        """
        """
        pass

    def tearDown(self):
        """
        """
        pass

    @patch('rest3client.ssladapter.ssl.SSLContext')
    def test__init__Should_SetAttributes_When_Certpass(self, ssl_context_patch, *patches):
        ssl_context_mock = Mock()
        ssl_context_patch.return_value = ssl_context_mock
        adapter = SSLAdapter(certfile='-certfile-', certpass='-certpass-')
        ssl_context_mock.load_cert_chain.assert_called_once_with('-certfile-', keyfile=None, password='-certpass-')
        self.assertEqual(adapter.ssl_context, ssl_context_mock)

    @patch('rest3client.ssladapter.ssl.SSLContext')
    def test__init__Should_SetAttributes_When_Certkey(self, ssl_context_patch, *patches):
        ssl_context_mock = Mock()
        ssl_context_patch.return_value = ssl_context_mock
        adapter = SSLAdapter(certfile='-certfile-', certkey='-certkey-')
        ssl_context_mock.load_cert_chain.assert_called_once_with('-certfile-', keyfile='-certkey-', password=None)
        self.assertEqual(adapter.ssl_context, ssl_context_mock)

    @patch('rest3client.ssladapter.requests.adapters.HTTPAdapter.init_poolmanager')
    @patch('rest3client.ssladapter.ssl.SSLContext')
    def test__init_poolmanager_Should_SetSSLContext_When_Called(self, ssl_context_patch, init_poolmanager_patch, *patches):
        ssl_context_mock = Mock()
        ssl_context_patch.return_value = ssl_context_mock
        adapter = SSLAdapter(certfile='-certfile-', certpass='-certpass-')
        adapter.init_poolmanager()
        init_poolmanager_patch.assert_called_with(ssl_context=ssl_context_mock)

    @patch('rest3client.ssladapter.requests.adapters.HTTPAdapter.proxy_manager_for')
    @patch('rest3client.ssladapter.ssl.SSLContext')
    def test__proxy_manager_for_Should_SetSSLContext_When_Called(self, ssl_context_patch, proxy_manager_for_patch, *patches):
        ssl_context_mock = Mock()
        ssl_context_patch.return_value = ssl_context_mock
        adapter = SSLAdapter(certfile='-certfile-', certpass='-certpass-')
        adapter.proxy_manager_for()
        proxy_manager_for_patch.assert_called_once_with(ssl_context=ssl_context_mock)
