# rest3client
[![GitHub Workflow Status](https://github.com/soda480/rest3client/workflows/build/badge.svg)](https://github.com/soda480/rest3client/actions)
[![Code Coverage](https://codecov.io/gh/soda480/rest3client/branch/master/graph/badge.svg)](https://codecov.io/gh/soda480/rest3client)
[![Code Grade](https://api.codiga.io/project/12271/status/svg)](https://app.codiga.io/public/project/12271/rest3client/dashboard)
[![vulnerabilities](https://img.shields.io/badge/vulnerabilities-None-brightgreen)](https://pypi.org/project/bandit/)
[![PyPI version](https://badge.fury.io/py/rest3client.svg)](https://badge.fury.io/py/rest3client)
[![python](https://img.shields.io/badge/python-3.7%20%7C%203.8%20%7C%203.9%20%7C%203.10-teal)](https://www.python.org/downloads/)

rest3client is an abstraction of the HTTP requests library (https://pypi.org/project/requests/) providing a simpler API for consuming HTTP REST APIs.

The library further abstracts the underlying HTTP requests methods providing equivalent methods for GET, POST, PATCH, PUT and DELETE. The library includes a RESTclient class that implements a consistent approach for processing request responses, extracting error messages from responses, providing standard headers to request methods, and enabling resiliency through integration with the retrying library. It also supports paging for REST APIs that leverage link headers. The abstraction enables the consumer to focus on their business logic and less on the complexites of setting up requests and processing request responses.

A subclass inheriting RESTclient can override the base methods providing further customization and flexibility including the ability to automatically retry on exceptions.


### Supported Authentication Schemes
The library supports most popular authentication schemes:
- No authentication
- Basic authentication
- API Key-based authentication
- Bearer token authentication
- Token authentication
- Certificate-based authentication
- JWT authentication

### Installation
```bash
pip install rest3client
```

### API Usage
The examples below show how RESTclient can be used to consume the GitHub REST API. However RESTclient can be used to consume just about any REST API.

```python
>>> from rest3client import RESTclient
```

`RESTclient` Authentication
```python
# no authentication
>>> client = RESTclient('api.github.com')

# basic authentication
>>> client = RESTclient('my-api.my-company.com', username='--my-user--', password='--my-password--')

# bearer token authentication
>>> client = RESTclient('api.github.com', bearer_token='--my-token--')

# token authentication
>>> client = RESTclient('codecov.io', token='--my-token--')

# certificate-based authentication
>>> client = RESTclient('my-api.my-company.com', certfile='/path/to/my-certificate.pem', certpass='--my-certificate-password--')

# jwt authentication
>>> client = RESTclient('my-api.my-company.com', jwt='--my-jwt--')
```

`GET` request
```python
# return json response
>>> client.get('/rate_limit')['resources']['core']
{'limit': 60, 'remaining': 37, 'reset': 1588898701}

# return raw resonse
>>> client.get('/rate_limit', raw_response=True)
<Response [200]>
```

`POST` request
```python
>>> client.post('/user/repos', json={'name': 'test-repo1'})['full_name']
'soda480/test-repo1'

>>> client.post('/repos/soda480/test-repo1/labels', json={'name': 'label1'})['url']
'https://api.github.com/repos/soda480/test-repo1/labels/label1'
```

`PATCH` request
```python
>>> client.patch('/repos/soda480/test-repo1/labels/label1', json={'description': 'my label'})['url']
'https://api.github.com/repos/soda480/test-repo1/labels/label1'
```

`PUT` request
```python
>>> client.put(endpoint, data=None, json=None, **kwargs)
```

`DELETE` request
```python
>>> client.delete('/repos/soda480/test-repo1')
```

`HEAD` request
```python
>>> response = client.head('/user/repos', raw_response=True)
>>> response.headers
```

#### Paging
Paging is provided for REST APIs that make use of [link headers](https://docs.python-requests.org/en/latest/user/advanced/#link-headers).

`GET all` directive - Get all pages from an endpoint and return list containing only matching attributes
```python
for repo in client.get('/orgs/edgexfoundry/repos', _get='all', _attributes=['full_name']):
    print(repo['full_name'])
```

`GET page` directive - Yield a page from endpoint
```python
for page in client.get('/user/repos', _get='page'):
    for repo in page:
        print(repo['full_name'])
```


#### Retries
Add support for retry using the `retrying` library: https://pypi.org/project/retrying/

Instantiating RESTclient with a `retries` key word argument will decorate all request methods (`get`, `put`, `post`, `delete` and `patch`) with a retry decorator using the provided arguments. For example, to retry on any error waiting 2 seconds between retries and limiting retry attempts to 3.
```python
>>> client = RESTclient('api.github.com', retries=[{'wait_fixed': 2000, 'stop_max_attempt_number': 3}])
```
Multiple retry specifications can be provided, however the arguments provided **must** adhere to the retrying specification.

Specifying retries for specific exceptions in subclasses is simple. RESTclient will automatically discover all retry methods defined in subclasses and decorate all request methods accordingly. Arguments for the retry decorator must be provided in the docstring for the respective retry method. Retry methods must begin with `retry_`.

For example:

```python
@staticmethod
def retry_connection_error(exception):
    """ return True if exception is ProxyError False otherwise
         retry:
            wait_random_min:10000
            wait_random_max:20000
            stop_max_attempt_number:6
    """
    if isinstance(exception, ProxyError):
        return True
    return False
```

Adding the method above to a subclass of RESTclient will have the affect of decorating all the request methods with the following decorator:

```python
@retry(retry_on_exception=retry_connection_error, 'wait_random_min'=10000, 'wait_random_max'=20000, 'stop_max_attempt_number'=6)
```

You also have the option of overriding any of the retry argument with environment variables. The environment variable must be of the form `${retry_method_name}_${argument}` in all caps. For example, setting the following environment variables will override the static settings in the `retry_connection_error` method docstring:

```bash
export RETRY_CONNECTION_ERROR_WAIT_RANDOM_MIN = 5000
export RETRY_CONNECTION_ERROR_WAIT_RANDOM_MAX = 15000
```

#### Real Eamples
See [GitHub3API](https://github.com/soda480/github3api) for an example of how RESTclient can be subclassed to provide further custom functionality for a specific REST API (including retry on exceptions). 

### CLI Usage
RESTclient comes packaged with a command line interace (CLI) that can be used to consume REST APIs using the RESTclient class. To consume the CLI simply build and run the Docker container as described below, except when building the image exclude the `--target build-image` argument.
```bash
usage: rest [-h] [--address ADDRESS] [--json JSON_DATA]
            [--headers HEADERS_DATA] [--attributes ATTRIBUTES] [--debug]
            [--raw] [--key]
            method endpoint

A CLI for rest3client

positional arguments:
  method                HTTP request method
  endpoint              REST API endpoint

optional arguments:
  -h, --help            show this help message and exit
  --address ADDRESS     HTTP request web address
  --json JSON_DATA      string representing JSON serializable object to send
                        to HTTP request method
  --headers HEADERS_DATA
                        string representing headers dictionary to send to HTTP
                        request method
  --attributes ATTRIBUTES
                        attributes to filter from response - if used with
                        --raw will filter from headers otherwise will filter
                        from JSON response
  --debug               display debug messages to stdout
  --raw                 return raw response from HTTP request method
  --key                 return key value in response - only if response is a
                        dictionary containing a single key value
```

Set environment variables prefixed with `R3C_`.

To set the web address of the API:
```bash
export R3C_ADDRESS=my-api.my-company.com
```

For bearer token authentication:
```bash
export R3C_BEARER_TOKEN=--my-token--
```

For token authentication:
```bash
export R3C_TOKEN=--my-token--
```

For basic authentication:
```bash
export R3C_USERNAME='--my-username--'
export R3C_PASSWORD='--my-password--'
```

For certificate-based authentication:
```bash
export R3C_CERTFILE='/path/to/my-certificate.pem'
export R3C_CERTPASS='--certificate-password--'
```

For jwt-based authentication:
```bash
export R3C_JWT=--my-jwt--
```

Some examples for how to execute the CLI to consume the GitHUB API:

```bash
rest POST /user/repos --json "{'name': 'test-repo1'}" --attributes "name, private, description, permissions"

rest GET /user/repos --attributes "name, full_name, private, description, permissions"

rest POST /repos/soda480/test-repo1/labels --json "{'name': 'label1', 'color': 'C7EFD5'}" --attributes url

rest PATCH /repos/soda480/test-repo1/labels/label1 --json "{'description': 'my label'}" --attributes url

rest DELETE /repos/soda480/test-repo1/labels/label1

rest GET /repos/soda480/test-repo1/labels --attributes name

rest DELETE /repos/soda480/test-repo1 --debug

rest GET /rate_limit --raw
```

### Development

Ensure the latest version of Docker is installed on your development server. Fork and clone the repository.

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
-v $PWD:/code \
rest3client:latest \
bash
```

Execute the build:
```sh
pyb -X
```

NOTE: commands above assume working behind a proxy, if not then the proxy arguments to both the docker build and run commands can be removed.
