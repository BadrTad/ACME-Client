import httpx
from acme_types import Json, URL


def fetch_directory(client: httpx.Client, url: URL) -> Json:
    response = client.get(url)
    if response.is_error:
        raise Exception("Error fetching directory", response.json())

    return response.json()
