# TODO: find a way to verify signature
# from jwcrypto import jwk as jwcrypto_jwk
# from jwcrypto import jws as jwcrypto_jws
# def verify_sign(signature, data) -> True:
#     import  hashlib
#     sk, vk = acme_debug.load_keypair("debug/sk.pem", "debug/vk.pem")
#     # to_sign = url64.encode(header) + "." + url64.encode(payload)
#     # sig_bytes = sk.sign_deterministic(to_sign.encode(), hashfunc=hashlib.sha256)
#     # return url64.encode(sig_bytes)

# return vk.verify(signature, data, hashfunc=hashlib.sha256)

# def test_jws_factory_build_JWS_with_jwk(crypto_keys):
#     jws_factory = JWSFactory(*crypto_keys)

#     jws_header = {"alg": "ES256", "url": "https://some_utl.com/1234", "nonce": "1234", "kid": "account_id_1234"}
#     # jws_payload = {"key1": "value2", "key2": ["value2","value3"], "key3": {"key4": "value4"}}
#     jws_payload = {"key1": "value2"}
#     jws = jws_factory.build_JWS_with_kid(jws_header, jws_payload)

#     assert 'protected' in jws
#     assert 'payload' in jws
#     assert 'signature' in jws

#     with open("debug/sk.pem", "rb") as f:
#         secret_key = f.read()

#     jws_json, sig = native(jws_header, jws_payload, secret_key)

#     assert sig == base64url_decode(jws_json['signature'])

#     assert jws_json['payload'] == jws['payload']
#     assert jws_json['protected'] == jws['protected']


#     data = url64.encode(jws_json['protected']) + "." + url64.encode(jws_json['payload'])
#     data = data.encode()
#     verification = verify_sign(sig, data)
#     assert verification == True

# def native(header: Json, payload: Json, secret_key: bytes) -> Json:
#     jwk  = jwcrypto_jwk.JWK.from_pem(secret_key)
#     jwk.update({"alg": "ES256", "use": "sig", "kty":'EC', "crv":'P-256', "size": 256})
#     jws = jwcrypto_jws.JWS(json.dumps(payload))
#     jws.add_signature(jwk, alg= 'ES256', protected = json.dumps(header))
#     return json.loads(jws.serialize()), jws.objects['signature']


# if __name__ == '__main__':
#     jws_header = {"url": "https://some_utl.com/1234", "nonce": "1234", "kid": "account_id_1234"}
#     jws_payload = {"key1": "value2", "key2": ["value2","value3"], "key3": {"key4": "value4"}}

#     with open("debug/sk.pem", "rb") as f:
#         secret_key = f.read()
#     #
