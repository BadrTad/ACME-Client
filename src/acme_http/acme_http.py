import threading
from typing import Optional
from flask import Flask, Response, request
import json


class ACME_DB:
    KEY_AUTHORIZATION_FILE = "debug/http_key_authorization.json"

    def __init__(self, path: str = KEY_AUTHORIZATION_FILE):
        self.path = path
        self.table = {}

    def add(self, key: str, value: str):
        self.table[key] = value
        with open(self.path, "w") as f:
            json.dump(self.table, f)
            f.flush()

    def remove(self, key: str):
        self.table.pop(key)
        with open(self.path, "w") as f:
            json.dump(self.table, f)
            f.flush()

    def get(self, key: str) -> Optional[str]:
        return self.table.get(key)

    def close(self):
        with open(self.path, "w") as f:
            f.write("{}")


app = Flask(__name__)
acme_db = ACME_DB()


def get_authorization_for_token(token: str) -> Optional[str]:
    return acme_db.get(token)


@app.route("/.well-known/acme-challenge/<string:token>", methods=["GET"])
def acme_challenge(token: str):
    key_authorization = get_authorization_for_token(token)

    if key_authorization is None:
        return Response("Not Found", status=404)

    response = Response(
        key_authorization, content_type="application/octet-stream", status=200
    )
    return response


def run_acme_http(address, port):
    def run():
        app.run(host=address, port=port, debug=False, use_reloader=False)

    thread = threading.Thread(target=run)
    thread.daemon = True
    thread.start()
