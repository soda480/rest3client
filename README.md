[![GitHub Workflow Status](https://github.com/soda480/rest3client/workflows/build/badge.svg)](https://github.com/soda480/rest3client/actions)
[![Code Coverage](https://codecov.io/gh/soda480/rest3client/branch/master/graph/badge.svg)](https://codecov.io/gh/soda480/rest3client)
[![Code Grade](https://www.code-inspector.com/project/12271/status/svg)](https://frontend.code-inspector.com/project/12271/dashboard)
[![PyPI version](https://badge.fury.io/py/rest3client.svg)](https://badge.fury.io/py/rest3client)

# rest3client #

rest3client is an abstraction of the HTTP requests library (https://pypi.org/project/requests/) providing a simpler interface to enable consumption of HTTP REST APIs.

The library further abstracts the underlying HTTP requests methods providing equivalent methods for GET, POST, PATCH, PUT and DELETE. The library includes a RESTclient class that implements a consistent approach for processing request responses, extracting error messages from responses, providing standard headers to request methods, and enabling request resiliency through integration with the retrying library. The abstraction enables the consumer to focus on their business logic and less on the complexites of setting up requests and processing request responses.

A subclass inheriting RESTclient can override the base methods providing further customization and flexibility including the ability to automatically retry on exceptions.


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

### API Usage ###
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

# token-based authentication
>>> client = RESTclient('api.github.com', bearer_token='--my-token--')

# certificate-based authentication
>>> client = RESTclient('my-api.my-company.com', certfile='/path/to/my-certificate.pem', certpass='--my-certificate-password--')
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

>>> client.post('/repos/soda480/test-repo1/labels', json={'name': 'label1', 'color': '#006b75'})['url']
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

#### Retries
Add support for retry using the `retrying` library: https://pypi.org/project/retrying/

Instantiating RESTclient with a `retries` key word argument will decorate all request methods (`get`, `put`, `post`, `delete` and `patch`) with a retry decorator using the provided arguments - i.e. wait 2 seconds between retries and limit retry attempts to 3.
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


#### Real Eamples
See [GitHub3API](https://github.com/soda480/github3api) for an example of how RESTclient can be subclassed to provide further custom functionality for a specific REST API (including retry on exceptions). 

### CLI Usage ###
RESTclient comes packaged with a command line interace (CLI) that can be used to consume REST APIs using the RESTclient class. To consume the CLI simply build and run the Docker container as described below, except when building the image exclude the `--target build-image` argument.
```bash
usage: rest [-h] [--address ADDRESS] [--json JSON_DATA]
            [--headers HEADERS_DATA] [--attributes ATTRIBUTES] [--debug]
            [--raw]
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
                        attributes in JSON response from HTTP request method
                        to filter out
  --debug               display debug messages to stdout
  --raw                 return raw response from HTTP request method
```

Set environment variables prefixed with `R3C_`.

To set the web address of the API:
```bash
export R3C_ADDRESS=my-api.my-company.com
```

For token-based authentication:
```bash
export R3C_BEARER_TOKEN=--my-token--
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
