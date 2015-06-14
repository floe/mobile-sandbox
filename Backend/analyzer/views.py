#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Author: Michael Spreitzenbarth (research@spreitzenbarth.de)
# Author: Paul Hofmann
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
#                                      Imports                                          #
#########################################################################################
from django.shortcuts import render_to_response, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.contrib.sessions.models import Session
from django.contrib.auth.models import User as DjangoUser
from django.db.models import Count
from tastypie.models import ApiKey
from django.template import RequestContext
from socket import inet_aton
from struct import unpack
import sys, traceback, tempfile, time, hashlib, os, shutil, json
import string, zipfile, subprocess, xmltodict, cgi, datetime
from analyzer.models import *
from raven.contrib.django.raven_compat.models import client
from django.http import Http404
from django.contrib.gis.geoip import GeoIP
import netaddr
# local imports
import parse_droidbox_json, pcap_parser, sqlite_parser
#########################################################################################
#                                 Global Variables                                      #
#########################################################################################
API_VERSION_HISTORY = {"0": "Android 1.0",
                       "1": "Android 1.0",
                       "2": "Android 1.1",
                       "3": "Android 1.5",
                       "4": "Android 1.6",
                       "5": "Android 2.0",
                       "6": "Android 2.0.1",
                       "7": "Android 2.1",
                       "8": "Android 2.2",
                       "9": "Android 2.3.0",
                       "10": "Android 2.3.4",
                       "11": "Android 3.0",
                       "12": "Android 3.1",
                       "13": "Android 3.2",
                       "14": "Android 4.0",
                       "15": "Android 4.0.4",
                       "16": "Android 4.1",
                       "17": "Android 4.2",
                       "18": "Android 4.3",
                       "19": "Android 4.4",
                       "20": "Android 4.4 Wear",
                       "xx": "Unknown"}
# live system
AAPT = '/usr/share/android-sdk/platform-tools/aapt'
#########################################################################################
#                                    Debugging                                          #
#########################################################################################
## debug begin
from django.core.signals import got_request_exception
def exception_printer(sender, **kwargs):
    print >> sys.stderr, ''.join(traceback.format_exception(*sys.exc_info()))
got_request_exception.connect(exception_printer)
## end debug
#########################################################################################
#                               Helper Functions                                        #
#########################################################################################
def parse_from_intermediate_db_format(valqueryset):
    resDict = dict()
    for row in valqueryset:
        fullFeature = row['feature']
        (featureCategory, featureName) = fullFeature.split('::', 1)
        featureCategory = string.replace(featureCategory, '_', ' ')
        if featureCategory == 's and r':
            featureCategory = 'services and receiver'
        ranking = row['ranking']
        if (featureCategory not in resDict) and (ranking != '0.0'):
            resDict[featureCategory] = []
            resDict[featureCategory].append({'feature' : featureName, 'ranking' : ranking})
    return  resDict

def getLtrace(sampleId):
    sha256 = Sample.objects.get(id=int(sampleId)).sha256
    workingDir = "/mobilesandbox/" + str(sha256) + "/"
    if os.path.isfile(workingDir + "/log/ltrace.log"):
        f = open(workingDir + "/log/ltrace.log", 'r')
        ltrace = ""
        ltraceInput = f.readlines()
        for line in ltraceInput:
            ltrace = ltrace + line + "<br><br>"
        return ltrace
    else:
        return False

def getPcap(sample):
    pcapFile = '/mobilesandbox/' + sample.sha256 + '/log/traffic.pcap'
    if os.path.isfile(pcapFile):
        return pcapFile
    else:
        return False

def getAndroidVersion(basicsDict):
    apkFileInfos = subprocess.Popen([AAPT, 'd', 'badging', basicsDict['newFilename']],
                                    stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
    apkFileInfos = apkFileInfos.communicate(0)[0].split("\n")
    sampleSdkVersion = 0
    for apkFileInfo in apkFileInfos:
        if apkFileInfo.startswith("sdkVersion"):
            sampleSdkVersion = apkFileInfo.split("'")[1]
            break
    try:
        androidVersion = API_VERSION_HISTORY[str(sampleSdkVersion)]
    except:
        androidVersion = API_VERSION_HISTORY['xx']
        client.captureMessage(message='Unknown Android SDK version found in Manifest',
                              level='warning',
                              extra={'sha256':basicsDict['sha256'],
                                     'sdkVersion':str(sampleSdkVersion)})
    return sampleSdkVersion, androidVersion

def getScreenshotList(sampleId):
    sampleFileName = Sample.objects.get(id=sampleId).package_name
    pngList = []
    if os.path.isfile('/home/webinterface/analyzer/static/screenshots/' + sampleFileName + '.png'):
        pngList.append('/static/screenshots/' + sampleFileName + '.png')
        return pngList
    else:
        return pngList

def handleUploadedFile(f, request):
    basicsDict = {}
    basicsDict['error_message'] = 'OK'
    #create TMP-file
    (dst, filename) = tempfile.mkstemp()
    dst = open(filename, 'wb')
    for chunk in f.chunks():
       dst.write(chunk)
    dst.close()
    fp = open(filename, 'rb')
    content = fp.read()
    # create a dictionary with important data from the submitted file
    newFilename = f.name
    newFilename = newFilename.replace(" ", "")
    newFilename = newFilename.replace("(", "")
    newFilename = newFilename.replace(")", "")
    newFilename = newFilename.replace("/", "")
    basicsDict['origfile'] = newFilename
    basicsDict['filesize'] = len(content)
    basicsDict['inserttime'] = int(time.time())
    basicsDict['md5'] = hashlib.md5(content).hexdigest()
    basicsDict['sha256'] = hashlib.sha256(content).hexdigest()
    # value of checkboxes
    if 'visibleforothers' in request.POST['optionsCheckboxes']:
        basicsDict['isPublic'] = 1
    else:
        basicsDict['isPublic'] = 0
    if 'emailNotification' in request.POST:
        if request.POST['emailNotification'] == "":
            basicsDict['email'] = "anonymous"
        else:
            basicsDict['email'] = request.POST['emailNotification']
    else:
        basicsDict['email'] = "anonymous"
    # check for valid apk file!
    try:
        a = zipfile.ZipFile(fp)
        if "classes.dex" in a.namelist():
            basicsDict['error_message'] = 'OK'
        else:
            client.captureMessage(message='An apk file without classes.dex has been submitted!',
                                  level='info',
                                  extra={'filename':str(basicsDict['origfile']), 'sha256':str(basicsDict['sha256'])},
                                  tags={'site':'index.html'})
            basicsDict['error_message'] = 'No valid Android apk file!'
            # return the dictionary
            return basicsDict
    except:
        client.captureMessage(message='An invalid apk file has been submitted!',
                              level='info',
                              extra={'filename':str(basicsDict['origfile']), 'sha256':str(basicsDict['sha256'])},
                              tags={'site':'index.html'})
        basicsDict['error_message'] = 'No valid apk file!'
        # return the dictionary
        return basicsDict
    fp.close()
    # create folder structure and move TMP-file or display error message
    newFolderName = '/mobilesandbox/' + hashlib.sha256(content).hexdigest()
    newSampleFolder = newFolderName + '/samples'
    newFilename = filter(lambda x: x in string.printable, newFilename)
    newFilename = newSampleFolder + '/' + newFilename.replace(" ", "")
    basicsDict['newFilename'] = newFilename
    try:
        os.mkdir(newFolderName)
        os.mkdir(newSampleFolder)
        shutil.move(filename, newFilename)
    except:
        if basicsDict['error_message'] == 'OK':
            try:
                sampleId = Sample.objects.get(sha256=basicsDict['sha256']).id
                basicsDict['error_message'] = 'This sample has already been uploaded! <br> You can find the report ' \
                                              '<a href="http://mobilesandbox.org/report/?q=' + str(sampleId) + '">here</a>!'
            except:
                client.captureMessage(message='An already submitted apk file has been submitted again!',
                                      level='info',
                                      extra={'sha256':str(basicsDict['sha256'])},
                                      tags={'site':'index.html'})
        else:
            print 'new sample submitted'
    # return the dictionary
    return basicsDict

def ip2long(ip_addr):
    ip_packed = inet_aton(ip_addr)
    ip = unpack("!L", ip_packed)[0]
    return ip

def submissionSQL(basicsDict):
    if basicsDict['error_message'] == "OK":
        # check if user exists in DB already
        userEntry = User.objects.all().filter(email=basicsDict['email'])
        if not userEntry:
            userEntry = User.objects.create(email=basicsDict['email'],
                                            priority=0,
                                            name='anonymous',
                                            role='user')
            userEntry.save()
            priority = 0
        else:
            priority = userEntry[0].priority
            userEntry = userEntry[0]
        # get the minimum sdk version of the app
        sampleSdkVersion, androidVersion = getAndroidVersion(basicsDict)
        # check if sample exists in DB already
        sampleEntry = Sample.objects.all().filter(sha256=basicsDict['sha256'])
        if not sampleEntry:
            malwareFamilyEntry, created = MalwareFamily.objects.get_or_create(family_name='untested')
            sampleEntry = Sample.objects.create(apk_name=basicsDict['origfile'],
                                                md5=basicsDict['md5'],
                                                sha256=basicsDict['sha256'],
                                                filesystem_position=basicsDict['newFilename'],
                                                malware_family_id=malwareFamilyEntry,
                                                os='android',
                                                android_version=androidVersion,
                                                min_sdk_version = int(sampleSdkVersion),
                                                status='idle')
        else:
            sampleEntry = sampleEntry[0]
        # insert submission into the DB
        date_of_submission = datetime.datetime.fromtimestamp(basicsDict['inserttime']).strftime('%Y-%m-%d %H:%M:%S')
        Submission.objects.create(uploader_id=userEntry,
                                  sample_id=sampleEntry,
                                  os='android',
                                  status='idle',
                                  date_of_submission=date_of_submission,
                                  run_name=basicsDict['origfile'],
                                  public=basicsDict['isPublic'])
        # insert the sample into the queue
        Queue.objects.create(priority=priority,
                             analyzer_type='static',
                             sample_id=sampleEntry,
                             status='idle', bot='',
                             android_version=sampleEntry.android_version,
                             min_sdk_version = sampleEntry.min_sdk_version,
                             public=basicsDict['isPublic'])
        Queue.objects.create(priority=priority,
                             analyzer_type='dynamic',
                             sample_id=sampleEntry,
                             status='idle',
                             bot='',
                             android_version=sampleEntry.android_version,
                             min_sdk_version = sampleEntry.min_sdk_version,
                             public=basicsDict['isPublic'])
        Queue.objects.create(priority=priority,
                             analyzer_type='AV',
                             sample_id=sampleEntry,
                             status='idle',
                             bot='',
                             android_version=sampleEntry.android_version,
                             min_sdk_version = sampleEntry.min_sdk_version,
                             public=basicsDict['isPublic'])
        Queue.objects.create(priority=priority,
                             analyzer_type='ML',
                             sample_id=sampleEntry,
                             status='idle',
                             bot='',
                             android_version=sampleEntry.android_version,
                             min_sdk_version = sampleEntry.min_sdk_version,
                             public=basicsDict['isPublic'])
        Queue.objects.create(priority=priority,
                             analyzer_type='SAAF',
                             sample_id=sampleEntry,
                             status='idle',
                             bot='',
                             android_version=sampleEntry.android_version,
                             min_sdk_version = sampleEntry.min_sdk_version,
                             public=basicsDict['isPublic'])
        SampleOrigin.objects.create(sample_id=sampleEntry, origin='user upload', download_data='unknown')
    else:
        print basicsDict['error_message']
#########################################################################################
#                                User Management                                        #
#########################################################################################
def loginError(request):
    message = "Please use the Login button on the top right!"
    return render_to_response('analyzer/login_error.html',
                              {'message': message},
                              context_instance=RequestContext(request))

def loginPage(request):
    # display the login view
    return render_to_response('analyzer/login.html',
                              context_instance=RequestContext(request))

@sensitive_post_parameters('username', 'password')
@csrf_protect
@never_cache
def loginVerification(request):
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(username=username, password=password)
    if user is not None:
        if user.is_active:
            login(request, user)
            # get the APIkey of the logged in user
            try:
                api_key = ApiKey.objects.get(user=user.id)
                api_key = api_key.key
            except:
                api_key = 'none'
            # Redirect to a success page.
            djangoUserDBEntry = DjangoUser.objects.get(id=user.id)
            return render_to_response('analyzer/members.html',
                                      {'api_key': api_key,
                                       'djangoUserDBEntry': djangoUserDBEntry},
                                      context_instance=RequestContext(request))
        else:
            # Return a 'disabled account' error message
            message = "Your account is disabled!"
            return render_to_response('analyzer/login_error.html',
                                      {'message': message},
                                      context_instance=RequestContext(request))
    else:
        # Return an 'invalid login' error message.
        message = "Wrong username or password!"
        return render_to_response('analyzer/login_error.html',
                                  {'message': message},
                                  context_instance=RequestContext(request))

def logoutPage(request):
    logout(request)
    # Redirect to a success page.
    return render_to_response('analyzer/logout.html',
                              context_instance=RequestContext(request))

@login_required(login_url='/login/')
@csrf_protect
@never_cache
def memberArea(request):
    # get the APIkey of the logged in user
    session_key = request.COOKIES['sessionid']
    session = Session.objects.get(session_key=session_key)
    uid = session.get_decoded().get('_auth_user_id')
    djangoUserDBEntry = DjangoUser.objects.get(id=uid)
    try:
        api_key = ApiKey.objects.get(user=uid)
        api_key = api_key.key
    except:
        api_key = 'none'
    # Redirect to Member Area.
    return render_to_response('analyzer/members.html',
                              {'api_key': api_key,
                               'djangoUserDBEntry': djangoUserDBEntry},
                              context_instance=RequestContext(request))

@login_required(login_url='/login/')
@csrf_protect
@never_cache
def memberReports(request):
    # get the user id of the logged in user
    session_key = request.COOKIES['sessionid']
    session = Session.objects.get(session_key=session_key)
    uid = session.get_decoded().get('_auth_user_id')
    apiKeyEntry = DjangoUser.objects.get(id=uid)
    apiUserMail = apiKeyEntry.email
    webUserEntry = User.objects.get(email=apiUserMail)
    submissionEntries = Submission.objects.filter(uploader_id=webUserEntry.id).order_by('-id')[:20]
    displayReport = []
    results = {}
    droidLyzerReports = {}
    droidBoxReports = {}
    saafReports = {}
    for submissionEntry in submissionEntries:
        displayReport.append(submissionEntry.sample_id.id)
    latestSamples = Sample.objects.filter(id__in=displayReport).order_by('id')
    latestSamples = latestSamples.reverse()[:20]
    for sampleEntry in latestSamples:
        foundDroidLyzerReports = Reports.objects.filter(sample_id=sampleEntry,
                                                        analyzer_id__tools_integrated__icontains='DroidLyzer').order_by('id')
        foundDroidBoxReports = Reports.objects.filter(sample_id=sampleEntry,
                                                      analyzer_id__tools_integrated__icontains='DroidBox').order_by('id')
        foundSaafReports = Reports.objects.filter(sample_id=sampleEntry,
                                                  analyzer_id__tools_integrated__icontains='SAAF').order_by('id')
        try:
            sampleInDb = Av.objects.filter(sample_id=sampleEntry)
            if sampleInDb[0].result == "Sample not in database!":
                result = 'unknown'
            else:
                result = Av.objects.filter(sample_id=sampleEntry).exclude(result='---').count()
                if result > 0:
                    result = 'malicious'
                else:
                    result = 'benign'
        except:
            result = 'scanning...'
        results[sampleEntry.id] = result
        droidLyzerReports[sampleEntry.id] = foundDroidLyzerReports
        droidBoxReports[sampleEntry.id] = foundDroidBoxReports
        saafReports[sampleEntry.id] = foundSaafReports
    count = Queue.objects.filter(status='idle', analyzer_type='static').count()
    count2 = Queue.objects.filter(status='idle', analyzer_type='dynamic').count()
    return render_to_response('analyzer/member_reports.html',
                              {'latest_samples': latestSamples,
                               'count':count,
                               'count2':count2,
                               'results':results,
                               'droidLyzerReports': droidLyzerReports,
                               'droidBoxReports': droidBoxReports,
                               'saafReports': saafReports},
                              context_instance=RequestContext(request))
#########################################################################################
#                                 Content Views                                         #
#########################################################################################
def apk(request):
    if 'q' in request.GET and request.GET['q']:
        query_string = int(request.GET['q'])
        try:
            found_entries = Reports.objects.filter(sample_id__exact=query_string, type_of_report='static')
            jsonFile = found_entries.values_list('filesystem_position')[0][0]
            jsonData = json.loads(open(jsonFile).read())
            md5 = jsonData['md5']
            sha256 = jsonData['sha256']
            ssdeep = jsonData['ssdeep']
            sampleID = Sample.objects.get(sha256=sha256).id
            apkName = jsonData['apk_name']
            packageName = jsonData['package_name']
            sdkVersion = jsonData['sdk_version']
            files = "<ul>"
            for element in jsonData['included_files']:
                files += "<li>"+str(element)+"</li>"
            files += "</ul>"
            query_string = ''
            return render_to_response('analyzer/apk.html',
                                      {'id':sampleID,
                                       'ssdeep':ssdeep,
                                       'query_string':query_string,
                                       'sha256':sha256,
                                       'md5':md5,
                                       'apk_name':apkName,
                                       'package_name':packageName,
                                       'sdk_version':sdkVersion,
                                       'files':files},
                                      context_instance=RequestContext(request))
        except:
            client.captureMessage(message='No matching sampleId found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'apk.html'})
            query_string = 'no matching sample'
            return render_to_response('analyzer/apk.html',
                                      {'query_string':query_string},
                                      context_instance=RequestContext(request))
    else:
        raise Http404

def av(request):
    if 'q' in request.GET and request.GET['q']:
        query_string = int(request.GET['q'])
        try:
            found_entries_av = Av.objects.filter(sample_id__exact=query_string).order_by('id')
            if len(found_entries_av) <= 2:
                found_entries_av = None
                client.captureMessage(message='No matching AV results found!',
                                      level='warning',
                                      extra={'query_string':query_string},
                                      tags={'site':'av.html'})
        except:
            client.captureMessage(message='No matching sampleId found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'av.html'})
            found_entries_av = "no matching av results found"
        return render_to_response('analyzer/av.html',
                                  {'query_string': query_string,
                                   'found_entries_av': found_entries_av},
                                  context_instance=RequestContext(request))
    else:
        raise Http404

def cert(request):
    if 'q' in request.GET and request.GET['q']:
        query_string = int(request.GET['q'])
        try:
            workingDir = "/mobilesandbox/" + Sample.objects.get(id__exact=query_string).sha256 + "/log/"
            if os.path.isfile(workingDir + "cert.log"):
                certinput = open(workingDir + "cert.log", "r")
                certinput = certinput.readlines()
                cert = ""
                for line in certinput:
                    cert = cert + line + "<br>"
            else:
                client.captureMessage(message='No matching certificate found!',
                                      level='info',
                                      extra={'query_string':query_string},
                                      tags={'site':'cert.html'})
                cert = "no certificate available"
        except:
            client.captureMessage(message='No matching sampleId found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'cert.html'})
            cert = "no matching sample"
        return render_to_response('analyzer/cert.html',
                                  {'query_string': query_string,
                                   'cert':cert},
                                  context_instance=RequestContext(request))
    else:
        raise Http404

def drebin(request):
    if 'q' in request.GET and request.GET['q']:
        query_string = int(request.GET['q'])
        try:
            found_entries_ml = Classifier.objects.filter(sample_id__exact=query_string).values()
            entries_dict = parse_from_intermediate_db_format(found_entries_ml)
        except:
            client.captureMessage(message='No matching DREBIN reports found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'drebin.html', 'report':'drebin'})
            entries_dict = None
        return render_to_response('analyzer/drebin.html',
                                  {'query_string': query_string,
                                   'entries_dict': entries_dict},
                                  context_instance=RequestContext(request))
    else:
        raise Http404

def ltrace(request):
    if 'q' in request.GET and request.GET['q']:
        query_string = int(request.GET['q'])
        try:
            ltrace = getLtrace(str(query_string))
        except:
            query_string = int(request.GET['q'])
            client.captureMessage(message='No matching LTRACE logs found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'ltrace.html', 'report':'ltrace'})
            ltrace = "no ltrace log available"
        return render_to_response('analyzer/ltrace.html',
                                  {'query_string': query_string,
                                   'ltrace':ltrace},
                                  context_instance=RequestContext(request))
    else:
        raise Http404

def network(request):
    if 'q' in request.GET and request.GET['q']:
        ipaddr = None
        conn_details = None
        try:
            found_logs = []
            query_string = int(request.GET['q'])
            sample = Sample.objects.get(id=query_string)
            conn_summary = pcap_parser.get_conn_summary_from_db(sample)
            if len(conn_summary) == 0:
                found_logs = ["no pcap data available"]
            for pcapConnSum in conn_summary:
                remotePort = '' if pcapConnSum[2] is None else ('on remote port %i' % pcapConnSum[2])
                direction = 'from' if pcapConnSum[3] == 'IN' else 'to'
                remoteIp = pcapConnSum[1]
                conn_type = pcapConnSum[0]
                number_of_conns = conn_summary[pcapConnSum]['number']
                if conn_summary[pcapConnSum]['expected']:
                    color = '#31ac31'
                elif conn_summary[pcapConnSum]['has_expected_attribs']:
                    color = '#ff9d00'
                else:
                    color = '#ff0000'
                expected_prepend = "<span style='color: %s'>" % color
                ip_addr_link = "<a href='/network/?q=%s&ip=%s'>%s</a>" % (query_string,
                                                                          remoteIp,
                                                                          remoteIp)
                found_logs.append("%s %ix %s %s %s %s</span>" % (expected_prepend,
                                                                 number_of_conns,
                                                                 conn_type,
                                                                 direction,
                                                                 ip_addr_link,
                                                                 remotePort))
            if 'ip' in request.GET and request.GET['ip']:
                try:
                    ipaddr = netaddr.IPAddress(request.GET['ip'])
                    pcapFile = getPcap(sample)
                    if not os.path.isfile(pcapFile):
                        conn_details = { 'error' : 'No PCAP file found' }
                        raise Exception('No PCAP file found')
                    else:
                        conn_details = pcap_parser.get_connection_details_from_pcap_file(pcapFile,
                                                                                         with_rawdata=True,
                                                                                         transform_local_addresses=True,
                                                                                         filter_ip=str(ipaddr))
                except netaddr.core.AddrFormatError:
                    conn_details = { 'error' : 'Invalid ip address' }
        except:
            found_logs = ["no pcap file available"]
            client.captureMessage(message='No matching PCAP files found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'network.html', 'report':'pcap'})
        return render_to_response('analyzer/network.html',
                                  {'query_string': query_string,
                                   'found_logs':found_logs,
                                   'ipaddr': ipaddr,
                                   'conn_details': conn_details},
                                  context_instance=RequestContext(request))
    else:
        raise Http404

def overview(request):
    if 'q' in request.GET and request.GET['q']:
        query_string = int(request.GET['q'])
        try:
            found_entries = Reports.objects.filter(sample_id__exact=query_string, type_of_report='static')
            found_answers = Overview.objects.filter(sample_id_id__exact=query_string)
            questions = {}
            jsonFile = found_entries.values_list('filesystem_position')[0][0]
            jsonData = json.loads(open(jsonFile).read())
            sha256 = jsonData['sha256']
            apk_name = jsonData['apk_name']
            package_name = jsonData['package_name']
            for i in range(01,25):
                j = str(i).zfill(2)
                found_answer = found_answers.values_list('q'+j)[0][0]
                if found_answer != 'no' and found_answer != 'n/a':
                    questions['q'+j] = 'yes'
                else:
                    questions['q'+j] = found_answer
            return render_to_response('analyzer/overview.html',
                              {'query_string': query_string,
                               'apk':apk_name,
                               'sha256':sha256,
                               'package':package_name,
                               'questions':questions,
                               'id':query_string},
                              context_instance=RequestContext(request))
        except:
            client.captureMessage(message='No matching sampleId found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'overview.html'})
            query_string = 'no matching sample'
            return render_to_response('analyzer/overview.html',
                                      {'query_string':query_string},
                                      context_instance=RequestContext(request))
    else:
        raise Http404

def report(request):
    if 'q' in request.GET and request.GET['q']:
        query_string = int(request.GET['q'])
        try:
            sampleEntry = Sample.objects.get(id__exact=query_string)
            found_entries_report = Reports.objects.filter(sample_id__exact=sampleEntry).order_by('id')
            sha = sampleEntry.sha256
            try:
                sampleInDb = Av.objects.filter(sample_id__exact=sampleEntry)
                if sampleInDb[0].result == "Sample not in database!":
                    DR = "Sample not in database!"
                else:
                    DRhit = Av.objects.filter(sample_id__exact=sampleEntry).exclude(result__exact='---').count()
                    DRall = Av.objects.filter(sample_id__exact=sampleEntry).count()
                    DR = str(DRhit) + " / " + str(DRall)
            except:
                DR = "scanning..."
            if found_entries_report:
                if len(Overview.objects.filter(sample_id_id__exact=query_string))>0:
                    overviewAvailable = 1
                else:
                    overviewAvailable = 0
                pngList = getScreenshotList(str(query_string))
                if len(pngList) == 0:
                    screenshotAvailable = 0
                else:
                    screenshotAvailable = 1
                found_logs = getPcap(sampleEntry)
                if found_logs:
                    pcapAvailable = 1
                else:
                    pcapAvailable = 0
                ltrace = getLtrace(str(query_string))
                if ltrace:
                    ltraceAvailable = 1
                else:
                    ltraceAvailable = 0
                png = "../static/icons/" + sha + ".png"
                try:
                    mlScore = ClassifiedApp.objects.get(sample_id__exact=sampleEntry).score
                    if float(mlScore) > 0:
                        mlScore = "benign (" + str(mlScore) + ")"
                    else:
                        mlScore = "malicious (" + str(mlScore) + ")"
                    ML = mlScore
                except:
                    ML = ''
                return render_to_response('analyzer/report.html',
                                          {'png':png,
                                           'query_string': query_string,
                                           'found_entries_report': found_entries_report,
                                           'DR': DR,
                                           'ML': ML,
                                           'screenshotAvailable': screenshotAvailable,
                                           'overviewAvailable': overviewAvailable,
                                           'pcapAvailable':pcapAvailable,
                                           'ltraceAvailable':ltraceAvailable},
                                          context_instance=RequestContext(request))
            else:
                client.captureMessage(message='No matching report found!',
                                      level='info',
                                      extra={'query_string':query_string},
                                      tags={'site':'report.html'})
                found_entries_report = None
                return render_to_response('analyzer/report.html',
                                          {'query_string': query_string, 'found_entries_report': found_entries_report},
                                          context_instance=RequestContext(request))
        except:
            client.captureMessage(message='No matching sampleId found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'report.html'})
            query_string = 'no matching sample'
            return render_to_response('analyzer/report.html',
                                      {'query_string':query_string},
                                      context_instance=RequestContext(request))
    else:
        raise Http404

def reports(request):
    submissionEntries = Submission.objects.filter(public=1).order_by('-id')[:10]
    displayReport = []
    results = {}
    for submissionEntry in submissionEntries:
        displayReport.append(submissionEntry.sample_id.id)
    latest_samples = Sample.objects.filter(id__in=displayReport).order_by('id')
    latest_samples = latest_samples.reverse()[:10]
    for sampleEntry in latest_samples:
        try:
            sampleInDb = Av.objects.filter(sample_id=sampleEntry)
            if sampleInDb[0].result == "Sample not in database!":
                result = 'unknown'
            else:
                result = Av.objects.filter(sample_id=sampleEntry).exclude(result='---').count()
                if result > 0:
                    result = 'malicious'
                else:
                    result = 'benign'
        except:
            result = 'scanning...'
        results[sampleEntry.id] = result
    count = Queue.objects.filter(status='idle', analyzer_type='static').count()
    count2 = Queue.objects.filter(status='idle', analyzer_type='dynamic').count()
    count3 = Sample.objects.filter(status='done').count()
    return render_to_response('analyzer/reports.html',
                              {'latest_samples': latest_samples,
                               'count':count,
                               'count2':count2,
                               'count3':count3,
                               'results':results},
                              context_instance=RequestContext(request))

def saaf_report(request):
    if 'q' in request.GET and request.GET['q']:
        query_string = int(request.GET['q'])
        try:
            found_entries = Reports.objects.filter(id__exact=query_string)
            filename = found_entries.values_list('filesystem_position')[0][0]
            SampleID = found_entries.values_list('sample_id')[0][0]
            def filter_backtracks(a):
                if a["value"] == None or len(a["value"]) < 2:
                    return False
                return True
            with open(filename) as fn:
                doc = xmltodict.parse(fn.read())
            try:
                backtracking = doc["analysis"]["backtracking-results"]["backtrack-result"]
                backtracking = filter(filter_backtracks, backtracking)
            except Exception:
                backtracking = "none"
                client.captureMessage(message='SAAF',
                                      level='error',
                                      extra={'exception':sys.exc_info()[0]},
                                      tags={'site':'saaf_report.html', 'report':'saaf'})
            try:
                heuristics = doc["analysis"]["heuristic-results"]["heuristic-result"]
            except Exception:
                heuristics = "none"
                client.captureMessage(message='SAAF',
                                      level='error',
                                      extra={'exception':sys.exc_info()[0]},
                                      tags={'site':'saaf_report.html', 'report':'saaf'})
            return render_to_response('analyzer/saaf_report.html',
                                      {'query_string':query_string,
                                       'backtracking': backtracking,
                                       'heuristics': heuristics,
                                       'id':SampleID},
                                      context_instance=RequestContext(request))
        except:
            client.captureMessage(message='No matching sampleId found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'saaf_report.html', 'report':'saaf'})
            query_string = "no matching sample"
            return render_to_response('analyzer/saaf_report.html',
                                      {'query_string': query_string},
                                      context_instance=RequestContext(request))
    else:
        raise Http404

def screenshots(request):
    if 'q' in request.GET and request.GET['q']:
        query_string = int(request.GET['q'])
        try:
            pngList = getScreenshotList(str(query_string))
            if len(pngList) > 0:
                return render_to_response('analyzer/screenshots.html',
                                          {'query_string': query_string,
                                           'pngList': pngList},
                                          context_instance=RequestContext(request))
            else:
                pngList = None
                return render_to_response('analyzer/screenshots.html',
                                          {'query_string': query_string,
                                           'pngList': pngList},
                                          context_instance=RequestContext(request))
        except:
            client.captureMessage(message='No matching sampleId found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'screenshots.html'})
            query_string = "no matching sample"
            return render_to_response('analyzer/screenshots.html',
                                      {'query_string': query_string,
                                       'id':query_string},
                                      context_instance=RequestContext(request))
    else:
        raise Http404

def search(request):
    # search for exact md5 hashes or for apk_names which start with the search term
    if 'q' in request.GET and request.GET['q']:
        query_string = str(request.GET['q'])
        found_entries = Sample.objects.filter(md5__exact=query_string).order_by('id')
        if found_entries:
            return render_to_response('analyzer/search.html',
                                      {'query_string': query_string,
                                       'found_entries': found_entries},
                                      context_instance=RequestContext(request))
        else:
            found_entries = Sample.objects.filter(sha256__exact=query_string).order_by('id')
            if found_entries:
                return render_to_response('analyzer/search.html',
                                          {'query_string': query_string,
                                           'found_entries': found_entries},
                                          context_instance=RequestContext(request))
            else:
                found_entries = Sample.objects.filter(ssdeep__exact=query_string).order_by('id')
                if found_entries:
                    return render_to_response('analyzer/search.html',
                                              {'query_string': query_string,
                                               'found_entries': found_entries},
                                              context_instance=RequestContext(request))
                else:
                    found_entries = Sample.objects.filter(package_name__icontains=query_string).order_by('id')
                    return render_to_response('analyzer/search.html',
                                              {'query_string': query_string,
                                               'found_entries': found_entries},
                                              context_instance=RequestContext(request))
    else:
        raise Http404

def submit(request):
    if request.method == 'POST':
        basicsDict = handleUploadedFile(request.FILES['file'], request)
        submissionSQL(basicsDict)
        g = GeoIP('/home/webinterface/analyzer/geoip_data/')
        client_address = request.META['REMOTE_ADDR']
        try:
            country = g.country(client_address)
        except:
            country = "---"
        UserIp.objects.create(date=datetime.datetime.today(), ip=str(client_address), country=str(country))
        return render_to_response('analyzer/submission.html',
                                  {'md5': basicsDict['md5'],
                                   'name': basicsDict['origfile'],
                                   'error_message': basicsDict['error_message']},
                                  context_instance=RequestContext(request))
    else:
        raise Http404

def xml_report_static(request):
    if 'q' in request.GET and request.GET['q']:
        query_string = int(request.GET['q'])
        try:
            found_entries = Reports.objects.filter(id__exact=query_string)
            jsonFile = found_entries.values_list('filesystem_position')[0][0]
            date1 = found_entries.values_list('start_of_analysis')[0][0]
            date2 = found_entries.values_list('end_of_analysis')[0][0]
            jsonData = json.loads(open(jsonFile).read())
            md5 = jsonData['md5']
            sha256 = jsonData['sha256']
            ssdeep = jsonData['ssdeep']
            sampleEntry = Sample.objects.get(sha256=sha256)
            sampleID = sampleEntry.id
            apkName = jsonData['apk_name']
            packageName = jsonData['package_name']
            sdkVersion = jsonData['sdk_version']
            permissions = "<ul>"
            for element in jsonData['app_permissions']:
                permissions += "<li>"+str(element)+"</li>"
            permissions += "</ul>"
            apiPermissions = "<ul>"
            for element in jsonData['api_permissions']:
                apiPermissions += "<li>"+str(element)+"</li>"
            apiPermissions += "</ul>"
            apiCalls = "<ul>"
            for element in jsonData['api_calls']:
                apiCalls += "<li>"+str(element[0])+"</li>"
            apiCalls += "</ul>"
            intents = "<ul>"
            for element in jsonData['intents']:
                intents += "<li>"+str(element)+"</li>"
            intents += "</ul>"
            activities = "<ul>"
            for element in jsonData['activities']:
                activities += "<li>"+str(element)+"</li>"
            activities += "</ul>"
            features = "<ul>"
            for element in jsonData['features']:
                features += "<li>"+str(element)+"</li>"
            features += "</ul>"
            urls = "<ul>"
            for element in jsonData['urls']:
                urls += "<li>"+str(element)+"</li>"
            urls += "</ul>"
            SR = "<ul>"
            for element in jsonData['s_and_r']:
                SR += "<li>"+str(element)+"</li>"
            SR += "</ul>"
            calls = "<ul>"
            for element in jsonData['interesting_calls']:
                calls += "<li>"+str(element)+"</li>"
            calls += "</ul>"
            providers = "<ul>"
            for element in jsonData['providers']:
                providers += "<li>"+str(element)+"</li>"
            providers += "</ul>"
            networks = "<ul>"
            for element in jsonData['networks']:
                networks += "<li>"+str(element)+"</li>"
            networks += "</ul>"
            query_string = ''
            return render_to_response('analyzer/xml_report_static.html',
                                      {'query_string':query_string,
                                       'ssdeep':ssdeep,
                                       'id':sampleID,
                                       'md5':md5,
                                       'sha256':sha256,
                                       'apk_name':apkName,
                                       'package_name':packageName,
                                       'sdk_version':sdkVersion,
                                       'real_permissions':apiPermissions,
                                       'api_calls':apiCalls,
                                       'permissions':permissions,
                                       'intents':intents,
                                       'urls':urls,
                                       'features':features,
                                       'serrecs':SR,
                                       'calls':calls,
                                       'providers':providers,
                                       'networks':networks,
                                       'date1':date1,
                                       'date2':date2,
                                       'activities':activities},
                                      context_instance=RequestContext(request))
        except:
            client.captureMessage(message='No matching sampleId found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'xml_report_static.html', 'report':'static'})
            query_string = "no matching sample"
            return render_to_response('analyzer/xml_report_static.html',
                                      {'query_string':query_string},
                                      context_instance=RequestContext(request))
    else:
        raise Http404

def xml_report_dynamic(request):
    if 'q' in request.GET and request.GET['q']:
        query_string = int(request.GET['q'])
        try:
            found_entries = Reports.objects.filter(id__exact=query_string)
            jsonFile = found_entries.values_list('filesystem_position')[0][0]
            date1 = found_entries.values_list('start_of_analysis')[0][0]
            date2 = found_entries.values_list('end_of_analysis')[0][0]
            droidbox_json = json.loads(open(jsonFile).read())
            all_db_infos = parse_droidbox_json.get_sqlite_data(droidbox_json, withCols=True)
            tables = []
            files = []
            cols_list = []
            for filename in all_db_infos:
                (status, db_infos) = all_db_infos[filename]
                if status == sqlite_parser.VALID_SQLITE_DB:
                    for tbl in db_infos:
                        tables.append(tbl['name'])
                        files.append("in %s" % filename)
                        cols_list.append(sqlite_parser.get_columns_as_html((tbl['columns'])))
                else:
                    tables.append("<span style='color: #f00; font-weight: bold'>Unable to open DB: %s</span>" % filename)
                    files.append(None)
                    failreason = 'Unknown'
                    if status == sqlite_parser.NO_SQLITE_DB:
                        failreason = 'Seems not to be a Sqlite DB at all.'
                    elif status == sqlite_parser.UNREADABLE_SQLITE_DB:
                        failreason = 'Sqlite DB seems to be damaged or encrypted.'
                    cols_list.append("REASON: %s" % failreason)
            sqlite_tables = parse_droidbox_json.get_list_as_html(header_list=tables, text_list=files, box_list=cols_list)
            (md5, sha, sha256) = parse_droidbox_json.get_hashes(droidbox_json)
            sampleEntry = Sample.objects.get(sha256=sha256)
            sampleID = sampleEntry.id
            NONE_HTML = parse_droidbox_json.get_list_as_html()
            # Single values / Lists
            apk_name = parse_droidbox_json.get_apk_name(droidbox_json)
            (md5, sha, sha256) = parse_droidbox_json.get_hashes(droidbox_json)
            enfpermissions_list = parse_droidbox_json.get_permissions(droidbox_json)
            # Dataframes
            df_crypto = parse_droidbox_json.get_crypto_usage(droidbox_json)
            df_dex = parse_droidbox_json.get_dexclasses(droidbox_json)
            df_broad = parse_droidbox_json.get_receivers(droidbox_json)
            df_service = parse_droidbox_json.get_service_starts(droidbox_json)
            df_sms = parse_droidbox_json.get_sent_sms(droidbox_json)
            df_calls = parse_droidbox_json.get_phonecalls(droidbox_json)
            df_fileaccesses = parse_droidbox_json.get_file_accesses(droidbox_json)
            df_leaks = parse_droidbox_json.get_dataleaks(droidbox_json)
            df_net_reqs = parse_droidbox_json.get_request_data(droidbox_json)
            json_activities = parse_droidbox_json.get_activity_data(droidbox_json, as_json=True)
            # File accesses
            file_lists = {'read': {'path':[], 'ts':[], 'rawdata':[]},
                          'write': {'path':[], 'ts':[], 'rawdata':[]}}
            fileac = dict()
            fileac['read'] = NONE_HTML
            fileac['write'] = NONE_HTML
            if len(df_fileaccesses) > 0:
                for (timestamp, operation, path, rawdata) in zip(df_fileaccesses['Timestamp'],
                                                                 df_fileaccesses['operation'],
                                                                 df_fileaccesses['path_unhexed'],
                                                                 df_fileaccesses['rawdata']):
                    rawdata = parse_droidbox_json.display_rawdata(rawdata)
                    rawdata = cgi.escape(rawdata)
                    file_lists[operation]['path'].append(path)
                    file_lists[operation]['ts'].append(" [%s]" % timestamp)
                    file_lists[operation]['rawdata'].append(rawdata)
                for op in ['read', 'write']:
                    fileac[op] = parse_droidbox_json.get_list_as_html(header_list=file_lists[op]['path'],
                                                                      text_list=file_lists[op]['ts'],
                                                                      box_list=file_lists[op]['rawdata'])
            # Network
            header_list = []
            box_list = []
            if len(df_net_reqs) > 0:
                for (endpoint, send_or_receive, rawdata) in zip(df_net_reqs['endpoint'],
                                                                df_net_reqs['send_or_receive'],
                                                                df_net_reqs['rawdata']):
                    rawdata = parse_droidbox_json.display_rawdata(rawdata)
                    rawdata = cgi.escape(rawdata)
                    tag = "SEND TO" if send_or_receive == "send" else "RECV FROM"
                    header_list.append("%s %s" % (tag, endpoint))
                    box_list.append(rawdata)
            networks = parse_droidbox_json.get_list_as_html(header_list=header_list, box_list=box_list)
            # Data leaks
            leaks = parse_droidbox_json.get_list_as_html(header_list=df_leaks['details'],
                                                         text_list=df_leaks['tag_list'],
                                                         box_list=df_leaks['rawdata']) \
                if len(df_leaks) > 0 else NONE_HTML
            # Permissions
            ENFpermissions = parse_droidbox_json.get_list_as_html(text_list=enfpermissions_list)
            # Crypto usage
            crypto = parse_droidbox_json.get_list_as_html(header_list=df_crypto['algorithm'],
                                                          text_list=df_crypto['operation'],
                                                          box_list=df_crypto['key_or_data']) \
                if len(df_crypto) > 0 else NONE_HTML
            # Dexclasses
            dex = parse_droidbox_json.get_list_as_html(text_list=df_dex['path']) \
                if len(df_dex) > 0 else NONE_HTML
            # BroadRecv
            broad = parse_droidbox_json.get_list_as_html(header_list=df_broad.keys(),
                                                         text_list=[" : %s" % intent for intent in df_broad.values()]) \
                if len(df_broad) > 0 else NONE_HTML
            # Service starts
            service = parse_droidbox_json.get_list_as_html(header_list=df_service['name'],
                                                           text_list=["[%s]" % ts for ts in df_service['Timestamp']]) \
                if len(df_service) > 0 else NONE_HTML
            # SMS
            sms = parse_droidbox_json.get_list_as_html(header_list=df_sms['type'],
                                                       text_list=["to %s" % nmb for nmb in df_sms['number']],
                                                       box_list=df_sms['message']) \
                if len(df_sms) > 0 else NONE_HTML
            # PhoneCalls
            calls = parse_droidbox_json.get_list_as_html(header_list=df_calls['number'],
                                                         text_list=["[%s]" % ts for ts in df_calls['Timestamp']]) \
                if len(df_calls) > 0 else NONE_HTML
            query_string = ''
            return render_to_response('analyzer/xml_report_dynamic.html',
                                      {'query_string':query_string,
                                       'id':sampleID,
                                       'service':service,
                                       'calls':calls,
                                       'date1':date1,
                                       'date2':date2,
                                       'md5':md5,
                                       'sha256':sha256,
                                       'sha':sha,
                                       'apk_name':apk_name,
                                       'ENFpermissions':ENFpermissions,
                                       'fileR':fileac['read'],
                                       'fileW':fileac['write'],
                                       'networks':networks,
                                       'sms':sms,
                                       'crypto':crypto,
                                       'dex':dex,
                                       'broad':broad,
                                       'leaks':leaks,
                                       'json_activities': json_activities,
                                       'sqlite_tables':sqlite_tables},
                                      context_instance=RequestContext(request))
        except:
            client.captureMessage(message='No matching sampleId found!',
                                  level='info',
                                  extra={'query_string':query_string},
                                  tags={'site':'xml_report_dynamic.html', 'report':'dynamic'})
            query_string = "no matching sample"
            return render_to_response('analyzer/xml_report_dynamic.html',
                                      {'query_string':query_string},
                                      context_instance=RequestContext(request))
    else:
        raise Http404
#########################################################################################
#                                   Design Views                                        #
#########################################################################################
def about(request):
    results = UserIp.objects.annotate(num_country=Count('country'))
    data = []
    for result in results:
        country = "'" + str(result.country.split("'")[3]) + "'"
        count = UserIp.objects.filter(country__exact=result.country).count()
        row = '[' + str(country) + ', ' + str(count) + '],'
        if row not in data:
            data.append(row)
        else:
            continue
    leng = len(data)/2
    return render_to_response('analyzer/about.html',
                              {'data': data,
                               'leng': leng},
                              context_instance=RequestContext(request))

def index(request):
    return render_to_response('analyzer/index.html',
                              context_instance=RequestContext(request))