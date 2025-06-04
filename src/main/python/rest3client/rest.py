import sys
import json
from rest3client import RESTcli
from requests.exceptions import HTTPError


def main():
    """ main function to instantiate and execute request method
    """
    try:
        RESTcli()
    except HTTPError as error:
        print(error)
        if error.response.headers.get('Content-Type', '') == 'application/json':
            try:
                print(json.dumps(error.response.json(), indent=2))
            except:
                print(error.response.text)
        sys.exit(1)
    except Exception as error:
        print(error)
        sys.exit(1)


if __name__ == '__main__':  # pragma: no cover

    main()
