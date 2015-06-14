#!/usr/bin/env python
#
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Author: Michael Spreitzenbarth (research@spreitzenbarth.de)
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
from django.conf.urls import patterns, url, include
from tastypie.resources import ModelResource
from tastypie.paginator import Paginator
from tastypie.http import *
from tastypie.utils import trailing_slash
from analyzer.models import *
from tastypie.authorization import DjangoAuthorization
from tastypie.authentication import ApiKeyAuthentication
import AV, report, api_submission, tempfile, classifier, os, shutil
import generateOverview, base64, datetime, sendMail
#########################################################################################
#                                 Paginators                                            #
#########################################################################################
class NoMetaAndLimitPaginator(Paginator):
    def get_limit(self):
        limit = 1
        return limit
    def page(self):
        output = super(NoMetaAndLimitPaginator, self).page()
        del output['meta']
        return output
#########################################################################################
#                                  Resources                                            #
#########################################################################################
class SampleResource(ModelResource):
    class Meta:
        queryset = Sample.objects.all()
        resource_name = 'sample'
        authentication = ApiKeyAuthentication()
        authorization = DjangoAuthorization()
        fields = ['id', 'sha256', 'package_name']
        allowed_methods = ['get']
#########################################################################################
class QueueResource(ModelResource):
    class Meta:
        queryset = Queue.objects.all()
        resource_name = 'queue'
        authentication = ApiKeyAuthentication()
        authorization = DjangoAuthorization()
        allowed_methods = ['get', 'post']

    def prepend_urls(self):
        return [
            url(r"^(?P<resource_name>%s)/idle_static%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('idle_static'), name="bot_api_idle_static"),
            url(r"^(?P<resource_name>%s)/done_static%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('done_static'), name="bot_api_done_static"),
            url(r"^(?P<resource_name>%s)/idle_dynamic%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('idle_dynamic'), name="bot_api_idle_dynamic"),
            url(r"^(?P<resource_name>%s)/done_dynamic%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('done_dynamic'), name="bot_api_done_dynamic"),
            url(r"^(?P<resource_name>%s)/idle_SAAF%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('idle_saaf'), name="bot_api_idle_saaf"),
            url(r"^(?P<resource_name>%s)/done_SAAF%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('done_saaf'), name="bot_api_done_saaf"),
            url(r"^(?P<resource_name>%s)/error_SAAF%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('error_saaf'), name="bot_api_error_saaf"),
            url(r"^(?P<resource_name>%s)/idle_av%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('idle_av'), name="bot_api_idle_av"),
            url(r"^(?P<resource_name>%s)/done_av%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('done_av'), name="bot_api_done_av"),
            url(r"^(?P<resource_name>%s)/submit_sample%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('submit_sample'), name="bot_api_submit_sample"),
            url(r"^(?P<resource_name>%s)/fail%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('fail'), name="bot_api_fail"),
            url(r"^(?P<resource_name>%s)/get_report%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('get_report'), name="bot_api_get_report"),
            url(r"^(?P<resource_name>%s)/get_info%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('get_info'), name="bot_api_get_info"),
            url(r"^(?P<resource_name>%s)/get_overview%s$" %
                (self._meta.resource_name, trailing_slash()), self.wrap_view('get_overview'), name="bot_api_get_overview"),
            ]

    def idle_static(self, request, **kwargs):
        # get IP of the bot
        botAddress = request.META.get('REMOTE_ADDR')
        # filter the queue for the oldest element which is idle and has the highest priority
        queryset = Queue.objects.all().filter(status='idle', analyzer_type='static').order_by('-priority', 'id')
        if queryset:
            result = Queue.__json__(queryset[0])
            queueElement = queryset[0]
            # Modify the queue entry
            queueEntry = Queue.objects.get(id=queueElement.id)
            queueEntry.bot = str(botAddress)
            queueEntry.status = str('running')
            queueEntry.save()
            # prepare the file for downloading
            sampleId = queueEntry.sample_id.id
            result['sample_id'] = sampleId
            sampleEntry = Sample.objects.get(id=sampleId)
            filename = sampleEntry.filesystem_position
            apkName = sampleEntry.apk_name
            sampleFile = open(filename, 'rb')
            encodedSampleFile = base64.b64encode(sampleFile.read())
            sampleFile.close()
            result.update({'sample':encodedSampleFile, 'name':apkName})
        else:
            result = 'NO NEW SAMPLE IN QUEUE'
        # return http response
        return self.create_response(request, result, response_class = HttpResponse)

    def done_static(self, request, **kwargs):
        queueId = request.REQUEST['queueId']
        queueEntry = Queue.objects.get(id=int(queueId))
        privacy = queueEntry.public
        if queueEntry.bot == request.META.get('REMOTE_ADDR'):
            # get sampleId from Queue
            sampleId = queueEntry.sample_id.id
            # get sample sha256 from Sample
            sampleEntry = Sample.objects.get(id=int(sampleId))
            sampleSHA256 = sampleEntry.sha256
            # set Queue entry to done
            queueEntry.status = 'done'
            queueEntry.save()
            # safe staticLogFile, staticReportFile, certFile and icon
            (dst, staticLogFile) = tempfile.mkstemp()
            uploadedFile = request.FILES['log']
            with open(staticLogFile, 'wb+') as destination:
                for chunk in uploadedFile.chunks():
                    destination.write(chunk)
                destination.close()
            (dst, staticReportFile) = tempfile.mkstemp()
            uploadedFile = request.FILES['report']
            with open(staticReportFile, 'wb+') as destination:
                for chunk in uploadedFile.chunks():
                    destination.write(chunk)
                destination.close()
            (dst, certFile) = tempfile.mkstemp()
            uploadedFile = request.FILES['cert']
            with open(certFile, 'wb+') as destination:
                for chunk in uploadedFile.chunks():
                    destination.write(chunk)
                destination.close()
            (dst, icon) = tempfile.mkstemp()
            uploadedFile = request.FILES['icon']
            with open(icon, 'wb+') as destination:
                for chunk in uploadedFile.chunks():
                    destination.write(chunk)
                destination.close()
            # further processing in seperate file
            staticReportFilesystemPosition = report.processStatic(staticLogFile,
                                                                  staticReportFile,
                                                                  icon,
                                                                  sampleSHA256,
                                                                  sampleId,
                                                                  privacy,
                                                                  certFile)
            # use machine learning classifier
            classifier.classify(staticReportFilesystemPosition, sampleEntry)
            # generate overview section
            generateOverview.gatherDataStatic(sampleId)
            # create dummy response
            result = 'ok'
            # send notification email
            sendMail.sendDoneNotification(sampleId)
            # return http response
            return self.create_response(request, result, response_class = HttpResponse)
        else:
            # create dummy response
            result = 'wrong analyzer ip'
            # return http response
            return self.create_response(request, result, response_class = HttpForbidden)

    def idle_av(self, request, **kwargs):
        # get IP of the bot
        botAddress = request.META.get('REMOTE_ADDR')
        # filter the queue for the oldest element which is idle and has the highest priority
        queryset = Queue.objects.all().filter(status='idle', analyzer_type='AV').order_by('-priority', 'id')
        if queryset:
            result = Queue.__json__(queryset[0])
            queueElement = queryset[0]
            # Modify the queue entry
            queueEntry = Queue.objects.get(id=queueElement.id)
            queueEntry.bot = str(botAddress)
            queueEntry.status = str('running')
            queueEntry.save()
            # prepare the file for downloading
            sampleId = queueEntry.sample_id.id
            result['sample_id'] = sampleId
            sampleEntry = Sample.objects.get(id=sampleId)
            filename = sampleEntry.filesystem_position
            sampleFile = open(filename, 'rb')
            encodedSampleFile = base64.b64encode(sampleFile.read())
            sampleFile.close()
            result.update({'sample':encodedSampleFile})
        else:
            result = 'NO NEW SAMPLE IN QUEUE'
        # return http response
        return self.create_response(request, result, response_class = HttpResponse)

    def done_av(self, request, **kwargs):
        queueId = request.REQUEST['queueId']
        queueEntry = Queue.objects.get(id=int(queueId))
        if queueEntry.bot == request.META.get('REMOTE_ADDR'):
            # get sampleId from Queue
            sampleId = queueEntry.sample_id.id
            # get sample sha256 from Sample
            sampleEntry = Sample.objects.get(id=int(sampleId))
            sampleSHA256 = sampleEntry.sha256
            # set Queue entry to done
            queueEntry.status = 'done'
            queueEntry.save()
            # decode vtLogFile
            vtLogFile = base64.b64decode(request.REQUEST['log'])
            # further processing in seperate file
            AV.processAV(vtLogFile, sampleSHA256, sampleId)
            # create dummy response
            result = 'ok'
            # return http response
            return self.create_response(request, result, response_class = HttpResponse)
        else:
            # create dummy response
            result = 'wrong analyzer ip'
            # return http response
            return self.create_response(request, result, response_class = HttpForbidden)

    def idle_dynamic(self, request, **kwargs):
        # get IP of the bot
        botAddress = request.META.get('REMOTE_ADDR')
        # filter the queue for the oldest element which is idle and has the highest priority
        queryset = Queue.objects.all().filter(status='idle', analyzer_type='dynamic', min_sdk_version__lte = 10).order_by('-priority', 'id')
        if queryset:
            result = Queue.__json__(queryset[0])
            queueElement = queryset[0]
            # Modify the queue entry
            queueEntry = Queue.objects.get(id=queueElement.id)
            queueEntry.bot = str(botAddress)
            queueEntry.status = str('running')
            queueEntry.save()
            # prepare the file for downloading
            sampleId = queueEntry.sample_id.id
            result['sample_id'] = sampleId
            sampleEntry = Sample.objects.get(id=sampleId)
            apkName = sampleEntry.apk_name
            pkgName = sampleEntry.package_name
            filename = sampleEntry.filesystem_position
            sampleFile = open(filename, 'rb')
            encodedSampleFile = base64.b64encode(sampleFile.read())
            sampleFile.close()
            result.update({'sample':encodedSampleFile, 'name':apkName, 'pname':pkgName})
        else:
            result = 'NO NEW SAMPLE IN QUEUE'
        # return http response
        return self.create_response(request, result, response_class = HttpResponse)

    def done_dynamic(self, request, **kwargs):
        queueId = request.REQUEST['queueId']
        queueEntry = Queue.objects.get(id=int(queueId))
        if queueEntry.bot == request.META.get('REMOTE_ADDR'):
            # get sampleId from Queue
            sampleId = queueEntry.sample_id.id
            # get sample sha256 from Sample
            sampleEntry = Sample.objects.get(id=int(sampleId))
            # set Queue entry to done
            queueEntry.status = 'done'
            queueEntry.save()
            # safe dynamicLogFile, screenshot, pcap and ltrace log files
            # - dynamicLogFile
            (dst, dynamicLogFile) = tempfile.mkstemp()
            uploadedFile = request.FILES['log']
            with open(dynamicLogFile, 'wb+') as destination:
                for chunk in uploadedFile.chunks():
                    destination.write(chunk)
                destination.close()
            print dynamicLogFile
            # - screenshot
            (dst, screenshot) = tempfile.mkstemp()
            uploadedFile = request.FILES['screenshot']
            with open(screenshot, 'wb+') as destination:
                for chunk in uploadedFile.chunks():
                    destination.write(chunk)
                destination.close()
            # - PCAP 
            (dst, pcap) = tempfile.mkstemp()
            uploadedFile = request.FILES['pcap']
            with open(pcap, 'wb+') as destination:
                for chunk in uploadedFile.chunks():
                    destination.write(chunk)
                destination.close()
            # - ltrace
            (dst, ltrace) = tempfile.mkstemp()
            uploadedFile = request.FILES['ltrace']
            with open(ltrace, 'wb+') as destination:
                for chunk in uploadedFile.chunks():
                    destination.write(chunk)
                destination.close()
            # - netstat_report
            (dst, netstat_report) = tempfile.mkstemp()
            uploadedFile = request.FILES['netstat_report']
            with open(netstat_report, 'wb+') as destination:
                for chunk in uploadedFile.chunks():
                    destination.write(chunk)
                destination.close()
            # - sqlite
            sqlite_files_count = request.REQUEST['sqlite_files_count']
            for idx in range(sqlite_files_count):
                (dst, sqlite_file) = tempfile.mkstemp()
                uploadedFile = request.FILES['sqlite_' + str(idx)]
                with open(sqlite_file, 'wb+') as destination:
                    for chunk in uploadedFile.chunks():
                        destination.write(chunk)
                    destination.close()
            # get starting time
            stime = request.REQUEST['stime']
            # update overview section
            generateOverview.gatherDataDynamic(sampleId)
            # further processing in seperate file
            report.processDynamic(pcap, dynamicLogFile, stime, screenshot, sampleEntry, ltrace)
            # create dummy response
            result = 'ok'
            # return http response
            return self.create_response(request, result, response_class = HttpResponse)
        else:
            # create dummy response
            result = 'wrong analyzer ip'
            # return http response
            return self.create_response(request, result, response_class = HttpForbidden)

    def idle_saaf(self, request, **kwargs):
        # get IP of the bot
        botAddress = request.META.get('REMOTE_ADDR')
        # filter the queue for the oldest element which is idle and has the highest priority
        queryset = Queue.objects.all().filter(status='idle', analyzer_type='SAAF').order_by('-priority', 'id')
        if queryset:
            result = Queue.__json__(queryset[0])
            queueElement = queryset[0]
            # Modify the queue entry
            queueEntry = Queue.objects.get(id=queueElement.id)
            queueEntry.bot = str(botAddress)
            queueEntry.status = str('running')
            queueEntry.save()
            # prepare the file for downloading
            sampleId = queueEntry.sample_id.id
            result['sample_id'] = sampleId
            sampleEntry = Sample.objects.get(id=sampleId)
            filename = sampleEntry.filesystem_position
            apkName = sampleEntry.apk_name
            sampleFile = open(filename, 'rb')
            encodedSampleFile = base64.b64encode(sampleFile.read())
            sampleFile.close()
            result.update({'sample':encodedSampleFile, 'name':apkName})
        else:
            result = 'NO NEW SAMPLE IN QUEUE'
        # return http response
        return self.create_response(request, result, response_class = HttpResponse)

    def done_saaf(self, request, **kwargs):
        queueId = request.REQUEST['queueId']
        queueEntry = Queue.objects.get(id=int(queueId))
        if queueEntry.bot == request.META.get('REMOTE_ADDR'):
            # get sampleId from Queue
            sampleId = queueEntry.sample_id.id
            # get sample sha256 from Sample
            sampleEntry = Sample.objects.get(id=int(sampleId))
            # set Queue entry to done
            queueEntry.status = 'done'
            queueEntry.save()
            # safe saafLogFile
            (dst, saafLogFile) = tempfile.mkstemp()
            uploadedFile = request.FILES['report']
            with open(saafLogFile, 'wb+') as destination:
                for chunk in uploadedFile.chunks():
                    destination.write(chunk)
                destination.close()
            timestamp = str(datetime.datetime.today()).split(' ')[0] + "_" + str(datetime.datetime.today()).split(' ')[1].split('.')[0]
            path = '/mobilesandbox/' + str(sampleEntry.sha256) + '/report/'
            if not os.path.exists(path):
                os.makedirs(path)
            saafLogFileName = path + 'saaf_' + timestamp + '.xml'
            shutil.move(saafLogFile, saafLogFileName)
            (analyzer,created) = Analyzer.objects.get_or_create(name='SAAF')
            try:
                Reports.objects.create(sample_id=sampleEntry,
                                       filesystem_position=saafLogFileName,
                                       type_of_report='SAAF',
                                       analyzer_id=analyzer,
                                       os='Android',
                                       start_of_analysis=str(datetime.datetime.today()),
                                       end_of_analysis=str(datetime.datetime.today()),
                                       public=queueEntry.public)
            except Exception as e:
                print e
            # create dummy response
            result = 'ok'
            # return http response
            return self.create_response(request, result, response_class = HttpResponse)
        else:
            # create dummy response
            result = 'wrong analyzer ip'
            # return http response
            return self.create_response(request, result, response_class = HttpForbidden)

    def submit_sample(self, request, **kwargs):
        (dst, tmpFile) = tempfile.mkstemp()
        uploadedFile = request.FILES['file']
        with open(tmpFile, 'wb+') as destination:
            for chunk in uploadedFile.chunks():
                destination.write(chunk)
        # get request infos
        fileName = str(request.REQUEST['name'])
        isPublic = int(request.REQUEST['isPublic'])
        email = str(request.REQUEST['email'])
        origin = str(request.REQUEST['origin'])
        # submit sample file to database
        uploadResultDict = api_submission.handleUploadedFile(fileName,tmpFile,isPublic,email,origin)
        if uploadResultDict['error_message'] == "OK":
            submissionResult = api_submission.submissionSQL(uploadResultDict)
            # create dummy response
            result = 'Sample submitted with ID ' + str(submissionResult.id)
            # return http response
            return self.create_response(request, result, response_class = HttpResponse)
        else:
            result = uploadResultDict['error_message']
            return self.create_response(request, result, response_class = HttpForbidden)

    def get_report(self, request, **kwargs):
        sampleId = int(request.REQUEST['sampleId'])
        reportType = str(request.REQUEST['reportType'])
        # filter the reports DB for reports matching the ask sample
        if reportType == 'static':
            queryset = Reports.objects.all().filter(status='done', sample_id__id=sampleId, type_of_report=reportType).order_by('-id')
        elif reportType == 'dynamic':
            queryset = Reports.objects.all().filter(status='done', sample_id__id=sampleId, type_of_report=reportType).order_by('-id')
        else:
            result = 'no matching report type: ' + reportType
            # return http response
            return self.create_response(request, result, response_class = HttpBadRequest)
        if queryset:
            reportElement = queryset[0]
            # prepare the file for downloading
            analyzer = reportElement.analyzer_id
            filename = reportElement.filesystem_position
            reportFile = open(filename, 'rb')
            encodedReportFile = base64.b64encode(reportFile.read())
            reportFile.close()
            reportFileName = str(analyzer.name).replace(' ', '') + "_" + "_".join(filename.split("/")[-1].split("_")[1:])
            result = {'report':encodedReportFile, 'name':reportFileName}
            # return http response
            return self.create_response(request, result, response_class = HttpResponse)
        else:
            result = 'no matching report available'
            # return http response
            return self.create_response(request, result, response_class = HttpBadRequest)

    def get_info(self, request, **kwargs):
        searchValue = str(request.REQUEST['searchValue'])
        searchType = str(request.REQUEST['searchType'])
        # filter the sample DB for samples matching the ask value
        if searchType == 'md5':
            queryset = Sample.objects.all().filter(md5=searchValue)
        elif searchType == 'sha256':
            queryset = Sample.objects.all().filter(sha256=searchValue)
        else:
            result = 'no matching search type: ' + searchType + ' please use md5 or sha256'
            # return http response
            return self.create_response(request, result, response_class = HttpBadRequest)
        if queryset:
            sampleElement = queryset[0]
            sampleOrigin = SampleOrigin.objects.all().filter(sample_id=sampleElement)
            ml_result = ClassifiedApp.objects.all().filter(sample_id=sampleElement)
            result = Sample.__json__(sampleElement)
            result['sample_origin'] = sampleOrigin[0].origin
            try:
                sampleInDb = Av.objects.filter(sample_id__exact=sampleElement)
                if sampleInDb[0].result == "Sample not in database!":
                    DR = "Sample not in database!"
                else:
                    DRhit = Av.objects.filter(sample_id__exact=sampleElement).exclude(result__exact='---').count()
                    DRall = Av.objects.filter(sample_id__exact=sampleElement).count()
                    DR = str(DRhit) + " / " + str(DRall)
            except:
                DR = "scanning..."
            if float(ml_result[0].score) < 0:
                result['drebin_score'] = "malicious (" + str(ml_result[0].score) + ")"
            else:
                result['drebin_score'] = "benign (" + str(ml_result[0].score) + ")"
            result['AV_detection_rate'] = DR
            # return http response
            return self.create_response(request, result, response_class = HttpResponse)
        else:
            result = 'no matching sample found'
            # return http response
            return self.create_response(request, result, response_class = HttpBadRequest)

    def get_overview(self, request, **kwargs):
        searchValue = str(request.REQUEST['searchValue'])
        searchType = str(request.REQUEST['searchType'])
        # filter the sample DB for samples matching the ask value
        if searchType == 'md5':
            queryset = Sample.objects.all().filter(md5=searchValue)
        elif searchType == 'sha256':
            queryset = Sample.objects.all().filter(sha256=searchValue)
        else:
            result = 'no matching search type: ' + searchType + ' please use md5 or sha256'
            # return http response
            return self.create_response(request, result, response_class = HttpBadRequest)
        if queryset:
            questions = {}
            found_answers = Overview.objects.filter(sample_id_id__exact=queryset[0])
            for i in range(01,25):
                j = str(i).zfill(2)
                found_answer = found_answers.values_list('q'+j)[0][0]
                if found_answer != 'no' and found_answer != 'n/a':
                    questions['q'+j] = found_answer.split('|')[:-1]
                else:
                    questions['q'+j] = found_answer
            # return http response
            return self.create_response(request, questions, response_class = HttpResponse)
        else:
            result = 'no matching sample found'
            # return http response
            return self.create_response(request, result, response_class = HttpBadRequest)
#########################################################################################