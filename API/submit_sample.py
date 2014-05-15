#!/usr/bin/env python
import sys, requests

# Authentication Parameters
# if you need an API key and user name please contact me
API_FORMAT = 'json'
API_USER = ''
API_KEY = ''

# parsing input parameters
if (len(sys.argv) < 5):
    print "Upload a suspicious Android app to the Mobile-Sandbox for analysis."
    print "Usage: %s requests [public submission (0,1)] [email adress] [apk_name] [apk_origin] [apk_file_location]" % sys.argv[0]
    print "If request contains a space, don't forget to surround it with \"\""
    sys.exit(0)

# building payload
payload = {'format':API_FORMAT,
           'username':API_USER,
           'api_key':API_KEY,
           'isPublic':str(sys.argv[1]), # has to be 0 for private submission or 1 for public submission
           'email':str(sys.argv[2]),
           'name':str(sys.argv[3]),
           'origin':str(sys.argv[4])}

# appending sample file
sampleFile = open(sys.argv[5], 'rb')
files = {'file':sampleFile}

# submitting sample file and meta data
print "------------------------------------------------------------------"
print "submitting sample..."
r = requests.post("http://mobilesandbox.org/api/bot/queue/submit_sample/", params=payload, files=files)

# printing results
print "submission result: " + r.text
print "------------------------------------------------------------------"

# cleanup
sampleFile.close()
