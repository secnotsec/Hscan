
import jwt
import sys
import json


private_key = '''-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDJtB8Gwpx57sK/qxFzlJAWi+0vjdztlVt+kn0PM2cpzagqeJIv \nPShWdvRCTLKYwR0H1+9EFYkMNCgkmMXikOlbNINgy5O0TAu74dDb5/hPsnRz339p \nNyAt2sS9bOIMjo2Aw2F/CrCoNKQq33Lj3fYskyFNK59o489DH2GNUeqJ8wIDAQAB \nAoGAWDtOhyqCQGRNFILEc4a9MN+stWydA+Cd0VRLGGcn7YVk1o8/gyKBjrEiUA40 \n4dU32cJ/i4zQEmKOXNPnXCB/svrLiNWiORelE7mwJvuiZbJgWQ9FGcewpTub8vaZ \nvh+HsxiojhvEKoGQnorIQSHFG9UtVaG1QvlrWcmzvnscZkECQQDu9dKARszt2l3r \nX7m/94ZiwMjpTHSGbJFsw0k4GHe0fqB3PTx7ECjAm01rOfnpMxgPbD0WD2GyPy5Y \n5bnGP3srAkEA2BYvcvULtqZsucqs9pdLpN/AHGY9Q8Wa9oOgsIxjTDyAfsJLBg0+ \nJJpQHkG8wM5jinKiuGqo3uxjBt8yGs4oWQJBALIxX9rGcTUBfL3zsUlkpLLpfijz \nGYXQWhWX/va00DcpojGo2XwPjcQrS20lW6Y5srx1g4v6xmisUrx5+rHKTucCQD1O \nvhOdlr8xpLNp33zvHBUhLn5gO42Y6Qh7/AFbM2kT2Vkdgu+qnjEAXy7Wc9k4NWG4 \neJZeHJ9y7f2rIaodR7ECQQDsJ+NBM8vIjNgT0r9ERIyG+kvPU1i+xR+koj5ZVGWL \n1O5UYCKeckGzT1EYlAKbNrd0LvFepgjo88kdLBHvC7YU \n-----END RSA PRIVATE KEY-----'''


def GenJwT(_payload_, key, algo, _headers_):
	print jwt.encode(_payload_, private_key, algorithm=algo, headers=_headers_)


if __name__ == '__main__':
	GenJwT(json.loads(sys.argv[1].replace("'","")), private_key, sys.argv[2], json.loads(sys.argv[3].replace("'","")))