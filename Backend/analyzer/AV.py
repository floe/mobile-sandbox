#!/usr/bin/env python
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
from analyzer.models import Av
from analyzer.models import MalwareFamily
from analyzer.models import Sample
import os
#########################################################################################
#                                    Functions                                          #
#########################################################################################
def clusterSample(sampleId, avResult):
    # check if malware family is allready known in database
    (malwareFamilyEntry, created) = MalwareFamily.objects.get_or_create(family_name=avResult)
    # update sample database entry with malware family id
    sampleObject = Sample.objects.get(id=int(sampleId))
    sampleObject.malware_family_id = malwareFamilyEntry
    sampleObject.save()

def processAV(vtLogFile, sampleSHA256, sampleId):
    # wirte VirusTotal log file to disk
    location = "/mobilesandbox/" + str(sampleSHA256) + "/av/"
    if not os.path.exists(location):
        os.mkdir(location)
    f = open(location + "VT.log", 'wb')
    f.write(vtLogFile)
    f.close()
    # filter VirusTotal results (skip date and last linebreak)
    results = vtLogFile.split("\n")[1:]
    # write VirusTotal results to database
    for result in results:
        if result.startswith("Sample"):
            avResult = "Sample not in database!"
            avEngine = "VirusTotal"
            sampleEntry = Sample.objects.get(id=sampleId)
            Av.objects.create(sample_id=sampleEntry, av_engine=avEngine, result=avResult)
            clusterSample(sampleId, avResult)
        else:
            try:
                avEngine = result.split(":")[0]
                avResult = result.split(":")[1]
                sampleEntry = Sample.objects.get(id=sampleId)
                Av.objects.create(sample_id=sampleEntry, av_engine=avEngine, result=avResult)
                if avEngine == "Kaspersky":
                    clusterSample(sampleId, avResult)
                else:
                    continue
            except:
                continue
#
## (c) 2013 by mspreitz