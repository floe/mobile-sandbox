#!/usr/bin/env python
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Will Holcomb (wholcomb@gmail.com)
# Michael Spreitzenbarth (research@spreitzenbarth.de)
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
#########################################################################################
#                          Imports  & Global Variables                                  #
#########################################################################################
import time, httplib, mimetypes, datetime, hashlib
import settings
from virustotal import VirusTotalAPI
#########################################################################################
#                                    Functions                                          #
#########################################################################################
def post_multipart(host, selector, fields, files):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    h = httplib.HTTPS(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()
    return h.file.read()

def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def virustotal(sampleFile, workingDir, privacy):
    AVReport = workingDir + "VirusTotal.log"
    md5 = hashlib.md5(sampleFile).hexdigest()
    print "VirusTotal scanning...."
    vt = VirusTotalAPI(settings.VTAPIKEY)
    try:
        result = vt.get_file_report(resource=md5)
    except:
        time.sleep(600)
        result = vt.get_file_report(resource=md5)
    f = open(AVReport, "a+")
    f.write(str(datetime.datetime.today()).split(' ')[0] + "_" + str(datetime.datetime.today()).split(' ')[1].split('.')[0] + "\n")
    if result['result'] != 1:
        print "VirusTotal return code: " + str(result['result'])
        if result['result'] == 0 and privacy == 1:
                try:
                    host = "www.virustotal.com"
                    api_url = "https://www.virustotal.com/vtapi/v2/file/scan"
                    fields = [("apikey", settings.VTAPIKEY)]
                    file_to_send = sampleFile
                    files = [("file", md5, file_to_send)]
                    json = post_multipart(host, api_url, fields, files)
                    f.write("Sample not in database!")
                except:
                    f.write("Sample not in database!")
        return False
    for AVEngine in result['report'][1]:
        if AVEngine == "Kaspersky":
            if result['report'][1][AVEngine] != "":
                AVNiceResult = result['report'][1][AVEngine].split(".")[:-1]
                AVNiceResult = ''.join(AVNiceResult)
                print "Kaspersky result:" + AVNiceResult
                if "OS" in AVNiceResult:
                    AVNiceResult = AVNiceResult.split("OS")[1]
                print "Kaspersky clustering: " + AVNiceResult
                f.write(AVEngine + ":" + AVNiceResult + "\n")
            else:
                AVNiceResult = "---"
                print "Kaspersky result: " + AVNiceResult
                f.write(AVEngine + ":" + AVNiceResult + "\n")
        else:
            try:
                if result['report'][1][AVEngine] != "":
                    AVNiceResult = result['report'][1][AVEngine]
                    f.write(AVEngine + ":" + AVNiceResult + "\n")
                else:
                    AVNiceResult = "---"
                    f.write(AVEngine + ":" + AVNiceResult + "\n")
            except:
                continue
    f.close()