"""Send example requests defined in testing_requests.json.

This script reads an array of request specifications from
``testing_requests.json`` and sends them using the ``requests`` library.
It is intended to generate traffic for the test REST service and exercise
the firewall.
"""

import json
import requests

def main() -> None:
    with open('testing_requests.json', 'r') as f:
        reqs = json.load(f)
    for req in reqs:
        try:
            requests.request(**req)
        except Exception as e:
            print(f"Error sending {req}: {e}")


if __name__ == '__main__':
    main()