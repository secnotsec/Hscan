
import jwt
import sys
import json

private_key = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAl02jsZRcv9e0U7gRrhioH4ZegmLNmRlu71CB/+eVBwyWuNmO
PtMgp6kPqgkxXpJjWh2dSfeTa48pBSlxioSVVmExXtAjHr54fYQvolSMiSbyeaZI
ScKkOBZ8t+6xl/nXlTzI1d+su+tBlHMB3F66Dz7eHwd+Hu5bLKhnKS6qkrpMB5oN
cLClkpXYuTU23ulEiNw4sBmQ+NUqTPkzJ6Sei8XVbV72/e7SGJlYSZcWRQ3QyGMV
+GhwIYm0Q0Dlm9pAtOUYoQHBF7aTXv6ZEWR8YntjLA0X7PIpHhtHf2OyJ9UBRCdK
SteDIlLAorpGgS/PL1CrlhIYfwb4AMPWW4eYoQIDAQABAoIBAHQEf6myVvBv6YFs
mnoBxCDwOtYGBxsHao4tEJH2tMqD96rkf3NjFx4Yv78lb2rSG0bFgI9wPOV0EAM6
RSrvAUgMHPxT4yo26VNtocz6wgyFBdcMD1An5R5w989eQ2WCmbGAu4tsCRrLiSzY
hyvAozD/hvkKGMaFBPqYYwosE3WQINclpz5xwE0o1w6bC2TMG78KYc8sYLR9Dvdd
5p--------------[RDACTED]------------------gXqe5APwO2nJ3RAiiXn7K
Iv4DmW1QYQbmFQVKHVUV1Fs7YLx1Sj/9leIeZmoPMYoqmnjA9AKAg2pxVvasapIz
JXyl8zPKR7akbMivh2EKqu/7aC2V8Qxn8FSE9VicgNeXqwq71se1KJacJ8JEsRGc
5Mv995j0B4JoSrE5pn9GvQKBgA6zr7gXA0IW0rCylJST3AgQiDkFdwTjol6ECc+w
I9Fe72TYLwG9lRVdzJi3X8+bXFdjfH4tCl5tW16gRyyNAVYk95eF6AvsB2VAfICe
UMKHJMvj+WYyg2N3lXUacN15Q2wwGuXJ9QIW1xbFCLCeXFnyN3QP92Wv9ejn6mZX
ly+VAoGAb56HKJ8PdabcQSTwOP+vqY5uy40btgbIzVaGwvux4EWxwm0hrGjjYMpJ
75Mlip6MUa08QK/ojz1qzyzgkaoqOUI4hrzXXgMFIXaOdpF8b6lSBGrfTmckrlBV
4hRBpD1P+Qu5sKcfZPna5ZKFiGL5ZMj+hRA2QfBDszoOMElu398=
-----END RSA PRIVATE KEY-----
'''

def GenJwT(_payload_, key, algo, _headers_):
	print jwt.encode(_payload_, private_key, algorithm=algo, headers=_headers_)


if __name__ == '__main__':
	GenJwT(json.loads(sys.argv[1].replace("'","")), private_key, sys.argv[2], json.loads(sys.argv[3].replace("'","")))
