#!/usr/bin/python
#
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
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
# python system imports
from analyzer.models import *
from django.core.mail import send_mail
#########################################################################################
#                                    Functions                                          #
#########################################################################################
def sendDoneNotification(sample_id):
    user = Submission.objects.get(sample_id_id__exact=sample_id).uploader_id
    user_name = User.objects.get(id__exact=user.id).name
    email = User.objects.get(id__exact=user.id).email
    if email != 'anonymous':
        # get AV results
        av_result = Av.objects.filter(sample_id_id__exact=sample_id).exclude(result='---').count()
        if av_result > 2: # using >2 because there are some AV engines that always say malicious
            av_result = 'malicious'
        else:
            av_result = 'benign'
        # get machine learning results
        ml_result = ClassifiedApp.objects.get(sample_id_id__exact=sample_id).score
        if float(ml_result) > 0:
            ml_result = "benign (" + str(ml_result) + ")"
        else:
            ml_result = "malicious (" + str(ml_result) + ")"
        apk_name = Sample.objects.get(id__exact=sample_id).apk_name
        package_name = Sample.objects.get(id__exact=sample_id).package_name
        body_text = 'Dear ' + user_name + ', \n' \
                    'the analysis of your sample with the apk name "' + apk_name + '" has left the static analysis and ' \
                    'will now be added to the queue for dynamic processing.\n\n' \
                    'The result of the AV detection is: ' + str(av_result) + \
                    '\n The result of the machine learning based detection is: ' + str(ml_result) + '\n\n\n' \
                    'The current state of analysis and all results can be found here: ' \
                    'http://mobilesandbox.org/report/?q=' + str(sample_id) + '\n\n\n' \
                    'Thank you very much for using the Mobile-Sandbox to check apps for malicious behaviour and please keep in mind: ' \
                    'This service is run purely as a research tool and a best effort service. We reserve the right to take it down at ' \
                    'any point for maintenance or other reasons.'
        subject = 'MobileSandbox: Results for sample ' + str(package_name)
        send_mail(subject, body_text, 'report@mobile-sandbox.com', [email], fail_silently=False)