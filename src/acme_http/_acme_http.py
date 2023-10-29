import threading
from flask import Flask, Response

from acme_http._acme_db import ACME_DB


class ACME_HTTP:
    KEY_AUTHORIZATION_FILE = "debug/http_key_authorization.json"

    _app = Flask(__name__)
    _acme_db = ACME_DB(KEY_AUTHORIZATION_FILE)

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    @_app.route("/.well-known/acme-challenge/<string:token>", methods=["GET"])
    def _acme_challenge(token: str):
        key_authorization = ACME_HTTP._acme_db.get(token)

        if key_authorization is None:
            return Response("Not Found", status=404)

        response = Response(
            key_authorization, content_type="application/octet-stream", status=200
        )
        return response

    def is_runnig(self):
        return bool(self._thread) and self._thread.is_alive()

    def run(self):
        """Starts an ACME HTTP challenge server in a new thread.

        Args:
            address (str): host of the server
            port (int): listening port
        """

        def run():
            ACME_HTTP._app.run(
                host=self.host, port=self.port, debug=False, use_reloader=False
            )

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def serve_key_authorization(self, token: str, key_authorization: str):
        """Serves a key authorization for a given token.

        Args:
            token (str): token
            key_authorization (str): key authorization
        """
        self._acme_db.add(token, key_authorization)

    def remove_key_authorization(self, token: str):
        """Removes a key authorization for a given token.

        Args:
            token (str): token
        """
        self._acme_db.remove(token)

    def stop(self):
        """Stops the ACME HTTP challenge server."""
        self._thread = None
        ACME_HTTP._acme_db.close()
