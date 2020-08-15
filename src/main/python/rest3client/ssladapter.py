
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

import ssl
import logging
import requests

logger = logging.getLogger(__name__)


class SSLAdapter(requests.adapters.HTTPAdapter):
    """ SSLAdapter class to provide SSL context for requests
    """

    def __init__(self, *args, **kwargs):
        certfile = kwargs.pop('certfile')
        certpass = str(kwargs.pop('certpass', ''))
        ssl_context = ssl.SSLContext()
        ssl_context.load_cert_chain(certfile, password=certpass)
        self.ssl_context = ssl_context
        super(SSLAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super(SSLAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super(SSLAdapter, self).proxy_manager_for(*args, **kwargs)
