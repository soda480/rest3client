[![GitHub Workflow Status](https://github.com/soda480/rest3client/workflows/build/badge.svg)](https://github.com/soda480/rest3client/actions)
[![Code Coverage](https://codecov.io/gh/soda480/rest3client/branch/master/graph/badge.svg)](https://codecov.io/gh/soda480/rest3client)
[![Code Grade](https://www.code-inspector.com/project/12271/status/svg)](https://frontend.code-inspector.com/project/12271/dashboard)
[![PyPI version](https://badge.fury.io/py/rest3client.svg)](https://badge.fury.io/py/rest3client)

# rest3client #

rest3client is a requests-based library providing simple methods to enable consumption of HTTP REST APIs.

The library further abstracts the underlying requests calls providing HTTP verb equivalent methods for GET, POST, PATCH, PUT and DELETE. The library includes a RESTclient class that implements a consistent approach for processing request responses, extracting error messages from responses, and providing standard headers to request calls. Enabling the consumer to focus on their business logic and less on the complexites of setting up and processing the requests repsonses.
A subclass inheriting RESTclient can override the base methods providing further customization and flexibility.

### Supported Authentication Schemes
The library supports most popular authentication schemes:
- No authentication
- Basic authentication
- API Key-based authentication
- Token-based authentication
- Certificate-based authentication

### Installation ###
```bash
pip install rest3client
```

### Example Usage ###
Examples below show how RESTclient can be used to consume the GitHub REST API. However RESTclient can be used to consume just about any REST API.

```python
>>> from rest3client import RESTclient

# instantiate RESTclient - no authentication
>>> client = RESTclient('api.github.com')

# GET request - return json response
>>> client.get('/rate_limit')['resources']['core']
{'limit': 60, 'remaining': 37, 'reset': 1588898701}

# GET request - return raw resonse
>>> client.get('/rate_limit', raw_response=True)
<Response [200]>

# instantiate RESTclient using bearer token authentication
>>> client = RESTclient('api.github.com', bearer_token='****************')

# POST request
>>> client.post('/user/repos', json={'name': 'test-repo1'})['full_name']
'soda480/test-repo1'

# POST request
>>> client.post('/repos/soda480/test-repo1/labels', json={'name': 'label1', 'color': '#006b75'})['url']
'https://api.github.com/repos/soda480/test-repo1/labels/label1'

# PATCH request
>>> client.patch('/repos/soda480/test-repo1/labels/label1', json={'description': 'my label'})['url']
'https://api.github.com/repos/soda480/test-repo1/labels/label1'

# DELETE request 
>>> client.delete('/repos/soda480/test-repo1')
```

#### Retries
Add support for retry using the `retrying` library: https://pypi.org/project/retrying/

The following will decorate all request methods with the retry decorator using the given arguments - randomly wait 1 to 2 seconds between retries
```python
>>> client = RESTclient('api.github.com', retries=[{'wait_random_min': 1000, 'wait_random_max': 2000}])
```

#### Real Eamples
See [GitHub3API](https://github.com/soda480/github3api) for an example of how RESTclient can be subclassed to provide further custom functionality for a specific REST API.

### Development ###

Ensure the latest version of Docker is installed on your development server.

Clone the repository:
```bash
cd
git clone https://github.com/soda480/rest3client.git
cd rest3client
```

Build the Docker image:
```sh
docker image build \
--target build-image \
--build-arg http_proxy \
--build-arg https_proxy \
-t \
rest3client:latest .
```

Run the Docker container:
```sh
docker container run \
--rm \
-it \
-e http_proxy \
-e https_proxy \
-v $PWD:/rest3client \
rest3client:latest \
/bin/sh
```

Execute the build:
```sh
pyb -X
```

NOTE: commands above assume working behind a proxy, if not then the proxy arguments to both the docker build and run commands can be removed.
