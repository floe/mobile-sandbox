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

# Questions answered in the response
questions = {'q01':'Does the app try to access the local address book', 
	'q02':'Does the app try to access the local calendar',
    'q03':'Does the app try to access stored pictures',
    'q04':'Does the app try to access configured accounts',
    'q05':'Does the app try to access the local SMS or MMS messages',
    'q06':'Does the app try to access device identifiers',
    'q07':'Does the app try to access SIM card identifiers',
    'q08':'Does the app make use of crypto operations',
    'q09':'Does the app load external libraries',
    'q10':'Does the app try to modify device settings',
    'q11':'Does the app try to install additional apps',
    'q12':'Does the app try to disable the screen lock',
    'q13':'Does the app embed ad networks',
    'q14':'Does the app try to use the camera',
    'q15':'Does the app try to use the microphone',
    'q16':'Does the app try to locate the device using the GPS sensor',
    'q17':'Does the app try to locate the device using network triangulation',
    'q18':'Does the app communicate with the Internet',
    'q19':'Does the app use cloud services',
    'q20':'Does the app try to send SMS messages',
    'q21':'Does the app try to start a phone call',
    'q22':'Does the app try to open local ports',
    'q23':'Does the app use local databases to store data',
    'q24':'Does the app use local storage (like SD card)'}

# submitting sample file and meta data
print "------------------------------------------------------------------"
r = requests.get("http://mobilesandbox.org/api/bot/queue/get_overview/", params=payload)

# printing result and writing report file to disk
if not r.status_code == requests.codes.ok:
    print "query result: \033[91m" + r.text + "\033[0m"
else:
    for key, value in r.json().iteritems():
    	key = questions[key]
        print key + ": \033[94m" + str(value) + "\033[0m"
print "------------------------------------------------------------------"
