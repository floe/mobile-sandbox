#!/usr/bin/env python
import sys, requests

# Authentication Parameters
# if you need an API key and user name please contact me
API_FORMAT = 'json'
API_USER = ''
API_KEY = ''

# parsing input parameters
if (len(sys.argv) < 3):
    print "Get infos to a specific Android app from the Mobile-Sandbox."
    print "Usage: %s requests [type (md5,sha256)] [value]" % sys.argv[0]
    sys.exit(0)

# building payload
payload = {'format':API_FORMAT,
           'username':API_USER,
           'api_key':API_KEY,
           'searchType':str(sys.argv[1]),   # has to be md5 or sha256
           'searchValue':str(sys.argv[2]),
}

# submitting sample file and meta data
print "------------------------------------------------------------------"
r = requests.get("http://mobilesandbox.org/api/bot/queue/get_info/", params=payload)

# printing result and writing report file to disk
if not r.status_code == requests.codes.ok:
    print "query result: \033[91m" + r.text + "\033[0m"
else:
    for key, value in r.json().iteritems():
        print key + ": \033[94m" + str(value) + "\033[0m"
print "------------------------------------------------------------------"
