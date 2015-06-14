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
from analyzer.models import *
import subprocess, dateutil.parser
#########################################################################################
#                                    Functions                                          #
#########################################################################################
def getCertInfos(certFileName, reportEntry):
    cert = subprocess.Popen(['keytool', '-printcert', '-file', certFileName], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    certData = cert.communicate(0)[0]
    cert = certData.split("\n")
    readableCertFile = open(certFileName + ".log", "a+")
    readableCertFile.write(certData)
    readableCertFile.close()
    if len(cert) > 3:
        for line in cert:
            if line.startswith("Owner:"):
                try:
                    ocn = line.split("CN=")[1].split(",")[0]
                except:
                    ocn = "not specified"
                try:
                    oou = line.split("OU=")[1].split(",")[0]
                except:
                    oou = "not specified"
                try:
                    oo = line.split("O=")[1].split(",")[0]
                except:
                    oo = "not specified"
                try:
                    ol = line.split("L=")[1].split(",")[0]
                except:
                    ol = "not specified"
                try:
                    ost = line.split("ST=")[1].split(",")[0]
                except:
                    ost = "not specified"
                try:
                    oc = line.split("C=")[1].split("\n")[0]
                except:
                    oc = "not specified"
            elif line.startswith("Issuer:"):
                try:
                    icn = line.split("CN=")[1].split(",")[0]
                except:
                    icn = "not specified"
                try:
                    iou = line.split("OU=")[1].split(",")[0]
                except:
                    iou = "not specified"
                try:
                    io = line.split("O=")[1].split(",")[0]
                except:
                    io = "not specified"
                try:
                    il = line.split("L=")[1].split(",")[0]
                except:
                    il = "not specified"
                try:
                    ist = line.split("ST=")[1].split(",")[0]
                except:
                    ist = "not specified"
                try:
                    ic = line.split("C=")[1].split("\n")[0]
                except:
                    ic = "not specified"
            elif line.startswith("Serial number:"):
                sn = line.split(": ")[1].split("\n")[0]
            elif line.startswith("\t SHA256"):
                sha256 = ''.join(line.split("SHA256: ")[1].split("\n")[0].split(":"))
            elif line.startswith("\t SHA1"):
                sha256 = ''.join(line.split("SHA1: ")[1].split("\n")[0].split(":"))
            elif line.startswith("\t MD5"):
                md5 = ''.join(line.split("MD5: ")[1].split("\n")[0].split(":"))
            elif line.startswith("Valid from:"):
                validFrom = line.split("Valid from: ")[1].split(" until:")[0]
                validUntil = line.split(" until: ")[1].split("\n")[0]
                # convert date and time
                validFrom = dateutil.parser.parse(validFrom).strftime('%Y-%m-%d %H:%M:%S')
                #INFO: problem with int_size on 32bit systems !
                #      if this script is running on a 64bit system only use line 111
                #      and delete lines 106 to 110
                originalValidUntil = validUntil.split(" ")[-1]
                if int(originalValidUntil) > 2037:
                    validUntil = ' '.join(validUntil.split(" ")[:-1]) + " 2037"
                    validUntil = dateutil.parser.parse(validUntil).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    validUntil = dateutil.parser.parse(validUntil).strftime('%Y-%m-%d %H:%M:%S')
            else:
                continue
        (certEntry, created) = Certs.objects.get_or_create(OCN=ocn,OOU=oou,OO=oo,OC=oc,OL=ol,OST=ost,ICN=icn,IOU=iou,IO=io,IC=ic,IL=il,IST=ist,sn=sn,fingerprint_md5=md5,fingerprint_sha256=sha256,validFrom=validFrom,validUntil=validUntil)
        UsedCerts.objects.create(report_id=reportEntry, cert_id=certEntry)