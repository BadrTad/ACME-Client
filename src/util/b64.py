import base64


def base64url_decode(payload):
    size = len(payload) % 4
    if size == 2:
        payload += "=="
    elif size == 3:
        payload += "="
    elif size != 0:
        raise ValueError("Invalid base64 string")
    return base64.urlsafe_b64decode(payload.encode("utf-8"))
