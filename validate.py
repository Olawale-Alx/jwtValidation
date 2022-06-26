import json
from jose import jwt
from urllib.request import urlopen


# Configurations
# Update the domain_name to reflect your auth0 domain name
domain_name = ""
ALGORITHM = ['RS256']
# Update the api_audience to the api audience in the api you're using for this application
api_audience = ""


# Exception for Authentication error
class AuthenticationError(Exception):
    def __init__(self, error, code):
        self.error = error
        self.code = code


# Paste your valid auth0 token from the login url
jwt_token = ""


def decode_jwt(token):
    # Gets the public key
    json_url = urlopen(f'https://{domain_name}/.well-known/jwks.json')
    jw_keys = json.loads(json_url.read())
    print(jw_keys)

    # Get the data in the header
    header = jwt.get_unverified_header(token)
    print(header)

    # Choose a key
    rsa_key = {}
    if 'kid' not in header:
        raise AuthenticationError({
            'code': 'Invalid header',
            'desc': 'Authorization not properly formed.'
        }, 401)

    for key in jw_keys['keys']:
        if key['kid'] == header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }

    # Verify if the rsa key is correct
    if rsa_key:
        try:
            # Use the key to validate the token
            payload = jwt.decode(token, rsa_key, algorithms=ALGORITHM,
                                 audience=api_audience,
                                 issuer=f'https://{domain_name}/')

            return payload

        except jwt.JWTClaimsError:
            raise AuthenticationError({
                'code': 'Invalid claims',
                'desc': 'Incorrect claims. Check audience and issuer.'
            }, 401)

        except jwt.ExpiredSignatureError:
            raise AuthenticationError({
                'code': 'Expired token',
                'desc': 'Token is expired.'
            }, 401)

        except Exception:
            raise AuthenticationError({
                'code': 'Invalid header',
                'desc': 'Not able to parse authentication.'
            }, 400)

    raise AuthenticationError({
        'code': 'Invalid header',
        'desc': 'Authorization not properly formed.'
    }, 400)


print(decode_jwt(jwt_token))
