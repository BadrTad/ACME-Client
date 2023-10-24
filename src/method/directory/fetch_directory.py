# import requests
import httpx
import ssl


from pprint import pprint


from acme_types import Json
from acme_debug import PROXIES, URL_ACME_DIR


def fetch_directory(url: str) -> Json:
    # context = ssl.create_default_context(cafile='./pebble_keys/pebble.minica.pem')
    #veridy = context
    with httpx.Client(verify=False, http2=True, proxies=PROXIES) as client:
        response = client.get(url)
        dir = response.json()
        pprint(dir)
        return dir
  

if __name__ == "__main__":
    fetch_directory(URL_ACME_DIR)


