#!/usr/bin/env python
import sys, requests, base64

# Authentication Parameters
# if you need an API key and user name please contact me
API_FORMAT = 'json'
API_USER = ''
API_KEY = ''

# parsing input parameters
if (len(sys.argv) < 4):
    print "Get the analysis reports from an already submitted app from the Mobile-Sandbox."
    print "Usage: %s requests [sample_id] [report_type (static, dynamic)] [destination_dir]" % sys.argv[0]
    sys.exit(0)

# building payload
payload = {'format':API_FORMAT,
           'username':API_USER,
           'api_key':API_KEY,
           'sampleId':str(sys.argv[1]),
           'reportType':str(sys.argv[2]),   # has to be static or dynamic depending on the type of report you like to get
}

# submitting sample file and meta data
print "------------------------------------------------------------------"
print "asking for " + str(sys.argv[2]) + " reports for the sample with ID " + str(sys.argv[1])
r = requests.get("http://mobilesandbox.org/api/bot/queue/get_report/", params=payload)

# printing result and writing report file to disk
if not r.status_code == requests.codes.ok:
    print "query result: \033[91m" + r.text + "\033[0m"
else:
    name = r.json()['name']
    print "report file saved at \033[94m" + str(name) + "\033[0m"
    # write report file to disk
    destinationDir = str(sys.argv[3])
    if destinationDir.endswith("/"):
        reportFile = open(destinationDir + name, 'a+')
    else:
        reportFile = open(destinationDir + "/" + name, 'a+')
    reportFile.write(base64.b64decode(r.json()['report']))
    reportFile.close()
print "------------------------------------------------------------------"
