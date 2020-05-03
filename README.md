# rest3client #

rest3client is a requests-based library providing simple methods to enable consumption of HTTP REST APIs.

The library further abstracts the underlying requests calls providing HTTP verb equivalent methods for GET, POST, PATCH, PUT and DELETE. The library includes a RESTclient class that implements a consistent approach for processing request responses, extracting error messages from responses, and providing standard headers to request calls. Enabling the consumer to focus on their business logic and less on the complexites of setting up and processing the requests repsonses.
A subclass inheriting RESTclient can override the base methods providing further customization and flexibility. The library supports most popular authentication schemes; including no-auth, basic auth, api-key and token-based.

### Installation ###
```bash
pip install git+https://gitlab.com/soda480/rest3client.git
```

### Example Usage ###
Examples below show how RESTclient can be used to consume the GitHub REST API. However RESTclient can be used to consume just about any REST API.

```python
>>> from rest3client import RESTclient

# instantiate RESTclient - no auth
>>> client = RESTclient('api.github.com')

# GET request - return json response
>>> client.get('/rate_limit')['resources']['core']
{'limit': 60, 'remaining': 37, 'reset': 1588898701}

# GET request - return raw resonse
>>> client.get('/rate_limit', raw_response=True)
<Response [200]>

# instantiate RESTclient using bearer token
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
--build-arg http_proxy \
--build-arg https_proxy \
-t rest3client:latest .
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
