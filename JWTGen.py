
import jwt
import sys
import json


private_key = '''
Private-key-Goes-Here
'''

def GenJwT(_payload_, key, algo, _headers_):
	print jwt.encode(_payload_, private_key, algorithm=algo, headers=_headers_)


if __name__ == '__main__':
	GenJwT(json.loads(sys.argv[1].replace("'","")), private_key, sys.argv[2], json.loads(sys.argv[3].replace("'","")))