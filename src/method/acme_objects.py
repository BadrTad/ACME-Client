from typing import Optional, List, Any
from acme_types import URL, Json

class Orders():

    def __init__(self, json: Json, order_url: str) -> None:
        self.expires = json.get('expires')
        self.status = json.get('status')
        self.orders = json.get('orders')
        self.identifiers = json.get('identifiers')
        self.authorizations = json.get('authorizations')
        self.finalize = json.get('finalize')
        self.order_url = order_url

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

# Quick test
if __name__ == "__main__":
    data = {
            "status": "valid",
            "contact": [
            "mailto:cert-admin@example.org",
            "mailto:admin@example.org"
            ],
            "termsOfServiceAgreed": True,
            "orders": "https://example.com/acme/orders/rzGoeA"
        }
        
    account = Account(data)
    print(account, account.contact, type(account.orders))
    
    