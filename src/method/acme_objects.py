from math import e
from typing import Optional, List, Any
from acme_types import URL, Json


class Orders():

    def __init__(self, json: Json, order_url: str) -> None:
        self.expires: str = json.get('expires')
        self.status: str = json.get('status')
        self.orders = json.get('orders')
        self.identifiers: list[Identifier] = [Identifier(json_identifier) for json_identifier in  json.get('identifiers')]
        self.authorizations: list[URL] = json.get('authorizations')
        self.finalize: URL = json.get('finalize')
        self.order_url: URL = order_url

    def __repr__(self) -> str:
        return f"""
        Orders:
            status: {self.status}
            orders: {self.orders}
            identifiers: {self.identifiers}
            authorizations: {self.authorizations}
            finalize: {self.finalize}
        """


class Account():

    def __init__(self, json: Json, kid: str) -> None:
        self.status: str = json.get("status")
        self.orders: URL = json.get("orders")
        self.contact: Optional[List[str]] = json.get("contact")
        self.termsOfServiceAgreed: Optional[bool] = json.get("termsOfServiceAgreed")
        self.externalAccountBinding: Optional[Any] = json.get("externalAccountBinding")
        self.kid = kid

    def __repr__(self) -> str:
        return f"""
        Account:
            status: {self.status}
            contact: {self.contact}
            orders: {self.orders}
            termsOfServiceAgreed: {self.termsOfServiceAgreed}
        """


class Identifier():
    def __init__(self, json: Json) -> None:
        self.type: str = json.get('type')
        self.value: str = json.get('value')

    def __repr__(self) -> str:
        return f"""
        Identifier:
            type: {self.type}
            value: {self.value}
        """
    def __eq__(self, __value: object) -> bool:
        if  isinstance(__value, Identifier):
            return self.value == __value.value and self.type == __value.type
        else:
            return False

    def as_json(self) -> Json:
        return {"type": self.type, "value": self.value}


class Challenge():
    def __init__(self, json: Json) -> None:
        self.type: str = json.get('type')
        self.url: URL = json.get('url')
        self.token: str = json.get('token')
        self.status: str = json.get('status')
        self.validated: Optional[str] = json.get('validated')
        self.error: Optional[Json] = json.get('error')

    def is_http_01(self) -> bool:
        return self.type == 'http-01'

    def is_dns_01(self) -> bool:
        return self.type == 'dns-01'

    def __repr__(self) -> str:
        return f"""
        Challenge:
            type: {self.type}
            url: {self.url}
            token: {self.token}
            status: {self.status}
            validated: {self.validated}
            error: {self.error}
        """


class Authorization():

    def __init__(self, json: Json, auth_url: URL) -> None:
        self.identifier: Identifier = Identifier(json.get('identifier'))
        self.status: str = json.get('status')
        self.expires: Optional[str] = json.get('expires')
        self.challenges: list[Challenge] =  [Challenge(json_challenge) for json_challenge in  json.get('challenges')]
        self.wildcard: Optional[bool] = json.get('wildcard')
        self.auth_url: URL = auth_url

    def __repr__(self) -> str:
        return f"""
            Authorization:
                identifier: {self.identifier}
                status: {self.status}
                expires: {self.expires}
                challenges: {self.challenges}
                wildcard: {self.wildcard}
            """

    def is_valid(self) -> bool:
        return self.status == 'valid'

    def is_still_pending(self) -> bool:
        return self.status == 'pending'

    def get_challenge_by_type(self, type: str) -> Optional[Challenge]:
        for challenge in self.challenges:
            if challenge.type == type:
                return challenge
        return None
        
    
