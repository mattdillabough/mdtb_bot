import base64
import binascii
from hashlib import sha1
import hmac
import json
import logging
import random
import sys
import time

import requests

log = logging.getLogger(__name__)

ENCODE_PASSTHROUGH = [
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
  'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
  'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
  'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '-', '.', '_', '~',
]

def generate_nonce():
  out = ''
  choices = ENCODE_PASSTHROUGH[:-4]
  for i in range(32):
    out += random.choice(choices)
  return out

def percent_encode(value):
  output = ''
  for letter in value:
    if letter in ENCODE_PASSTHROUGH:
      output += letter
    else:
      utf8_bytes = binascii.hexlify(letter.encode('utf-8')).decode('utf-8')
      for i in range(0, len(utf8_bytes), 2):
        output += '%' + utf8_bytes[i:i+2].upper()
  return output

# assert(percent_encode('abcdef') == 'abcdef')
# assert(percent_encode('Python is fun!') == 'Python%20is%20fun%21')
# assert(percent_encode('☃') == '%E2%98%83')

def collect_parameters(params):
  out = ''
  new_params = {}
  for key, value in params.items():
    new_params[percent_encode(key)] = percent_encode(value)
  for i, key in enumerate(sorted(new_params.keys())):
    out += key + '=' + new_params[key]
    if i < len(new_params) - 1:
      out += '&'
  return out

def create_sig_base_string(method, url, param_string):
  return (method.upper() + '&' + percent_encode(url) + '&' + 
          percent_encode(param_string))

def get_signing_key(consumer_secret, oauth_token_secret):
  return (percent_encode(consumer_secret) + '&' + 
          percent_encode(oauth_token_secret))

def generate_auth_header(params):
  parts = []
  for key, value in params.items():
    parts.append('%s="%s"' % (percent_encode(key), percent_encode(value)))
  return 'OAuth ' + ', '.join(parts)

def post_tweet(status):
  secrets = json.load(open('secrets.json'))

  consumer_secret = secrets.get('CONSUMER_SECRET')
  oauth_token_secret = secrets.get('OAUTH_TOKEN_SECRET')
  oauth_consumer_key = secrets.get('OAUTH_CONSUMER_KEY')
  oauth_token = secrets.get('OAUTH_TOKEN')

  if (not consumer_secret or not oauth_token_secret or not oauth_consumer_key or
      not oauth_token):
    print(consumer_secret)
    print(oauth_token_secret)
    print(oauth_consumer_key)
    print(oauth_token)
    sys.stderr.write('Missing CONSUMER_SECRET or OAUTH_TOKEN_SECRET or '
                     'OAUTH_CONSUMER_KEY or OAUTH_TOKEN in env variables\n')
    sys.exit(1)

  oauth_params = {
    'oauth_consumer_key': oauth_consumer_key,
    'oauth_nonce': generate_nonce(),
    'oauth_signature_method': 'HMAC-SHA1',
    'oauth_timestamp': str(int(time.time())),
    'oauth_token': oauth_token,
    'oauth_version': '1.0'
  }

  post_params = {
    'status': status,
  }
  post_params.update(oauth_params)

  http_method = 'POST'
  base_url = 'https://api.twitter.com/1.1/statuses/update.json'

  param_string = collect_parameters(post_params)
  log.debug(param_string)

  sig_base_string = create_sig_base_string(http_method, base_url, param_string).encode('utf-8')
  log.debug(sig_base_string)

  signing_key = get_signing_key(consumer_secret, oauth_token_secret).encode('utf-8')
  log.debug(signing_key)

  oauth_signature = base64.b64encode(
    hmac.new(signing_key, sig_base_string, sha1).digest())
  log.debug(oauth_signature)

  oauth_params['oauth_signature'] = oauth_signature.decode('utf-8')

  auth_header = generate_auth_header(oauth_params)
  log.debug(auth_header)

  r = requests.post(
    base_url,
    data=post_params,
    headers={'Authorization': auth_header})
  log.debug(r.text)

