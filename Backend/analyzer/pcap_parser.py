#!/usr/bin/env python
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2013, Mobile-Sandbox
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
#                          Imports  & Global Variables                                  #
#########################################################################################
from analyzer.models import PcapData
from scapy.all import *
import scapy_http.http, netaddr, cgi

scapyIp = IP
scapyIpv6 = IPv6
scapyARP = ARP
scapyTcp = TCP
scapyUdp = UDP
scapyIcmp = ICMP
scapyRaw = Raw
scapyDNSRR = DNSRR
scapyHTTP = scapy_http.http.HTTP
scapyHTTPRequest = scapy_http.http.HTTPRequest
scapyHTTPResponse = scapy_http.http.HTTPResponse

# source: http://en.wikipedia.org/wiki/List_of_DNS_record_types
DNS_RR_TYPE = {
                'A': 1,
                'AAAA': 28,
                'AFSDB' : 18,
                'APL' : 42,
                'CAA' : 257,
                'CDNSKEY' : 60,
                'CDS' : 59,
                'CERT' : 37,
                'CNAME': 5,
                'DHCID' : 49,
                'DLV' : 32769,
                'DNAME' : 39,
                'DNSKEY' : 48,
                'DS' : 43,
                'HIP' : 55,
                'IPSECKEY' : 45,
                'KEY' : 25,
                'KX' : 36,
                'LOC' : 29,
                'MX' : 15,
                'NAPTR' : 35,
                'NS' : 2,
                'NSEC' : 47,
                'NSEC3' : 50,
                'NSEC3PARAM' : 51,
                'PTR' : 12,
                'RRSIG' : 46,
                'RP' : 17,
                'SIG' : 24,
                'SOA' : 6,
                'SPF' : 99,
                'SRV' : 33,
                'SSHFP' : 44,
                'TA' : 32768,
                'TKEY' : 249,
                'TLSA' : 52,
                'TSIG' : 250,
                'TXT' : 16,
                # pseudo record types:
                '*' : 255,
                'AXFR' : 252,
                'IXFR' : 251,
                'OPT' : 41,
                }

EXPECTED_CONN_IDS = (
                     ('IPv6', '::', None, 'IN'),
                     )
#########################################################################################
#                               Helper Functions                                        #
#########################################################################################
def is_local_multicast(ipaddr):
    ipaddr = ipaddr.ipv6()
    ipaddr_val = ipaddr.value
    prefix_and_flags = ipaddr_val >> 16*7   # shift by 7 blocks with 16 bit each 
    scope_flag = prefix_and_flags & 0x000f
    prefix = prefix_and_flags >> 8
    if prefix != 0xff:
        return False
    return scope_flag in (1, 2)
    
def is_local_address(addr):
    # TODO: Is that test really valid?
    ipaddr = netaddr.IPAddress(addr)
    return ipaddr.is_loopback() or ipaddr.is_private() or ipaddr.is_link_local() or is_local_multicast(ipaddr)

def transform_local_address(addr):
    if is_local_address(addr):
        return 'LOCAL_SEGMENT'
    else:
        return addr

def is_local_traffic(packet):
    ip_lay = None
    if packet.haslayer(scapyIp):
        ip_lay = packet.getlayer(scapyIp)
    elif packet.haslayer(scapyIpv6):
        ip_lay = packet.getlayer(scapyIpv6)
    if ip_lay is None:
        # cannot be determined
        return False
    if is_local_address(ip_lay.fields['src']) and is_local_address(ip_lay.fields['dst']):
        return True
    return False

def is_arp_package(packet):   
    return packet.haslayer(scapyARP)

def get_best_known_connection_type(packet):
    ## Network Layer ##
    if packet.haslayer(scapyIp):
        conn_type = 'IPv4'
    elif packet.haslayer(scapyIpv6):
        conn_type = 'IPv6'  
    else:
        return 'Unknown'
    ## Transport Layer ##
    if packet.haslayer(scapyTcp):
        conn_type = 'TCP'
    elif packet.haslayer(scapyUdp):
        conn_type = 'UDP'
    elif packet.haslayer(scapyIcmp):
        conn_type = 'ICMP'
    return conn_type

def get_conn_direction(pcapConn):
    if is_local_address(pcapConn.src) and is_local_address(pcapConn.dst):
        return 'LOCAL'
    elif is_local_address(pcapConn.src):
        return 'OUT'
    elif is_local_address(pcapConn.dst):
        return 'IN'
    else:
        raise Exception('This connection is neither outgoing, ingoing nor local')
    
def has_expected_attribs(conn_id):
    remotePort = conn_id[2]
    if remotePort == 123:
        return True
    return False

#########################################################################################
#                                Main Functions                                         #
#########################################################################################
def parse_from_file_to_db(filename, sample):
    ip_conns = get_connection_details_from_pcap_file(filename, hide_local_traffic=True,
                                                     with_rawdata=False,
                                                     transform_local_addresses=False)
    for ip_conn in ip_conns:
        pcapData = PcapData()
        pcapData.sample_id = sample
        pcapData.timestamp = ip_conn['timestamp']
        pcapData.conn_type = ip_conn['conn_type']
        pcapData.src = ip_conn['src']
        pcapData.dst = ip_conn['dst']
        pcapData.sport = ip_conn['sport']
        pcapData.dport = ip_conn['dport']
        pcapData.save()      
            
def get_conn_summary_from_db(sample):
    pcapData = PcapData.objects.filter(sample_id__exact=sample.id)
    ip_connections = dict()
    for pcapConn in pcapData:
        # Ignore LOCAL; Local connections are filtered beforehand
        conn_direction = get_conn_direction(pcapConn)
        remotePort = pcapConn.sport if conn_direction == 'IN' else pcapConn.dport
        remoteIp = pcapConn.src if conn_direction == 'IN' else pcapConn.dst
        conn_id = (pcapConn.conn_type, remoteIp, remotePort, conn_direction)
        if conn_id in ip_connections:
            ip_connections[conn_id]['number'] += 1
        else:
            ip_connections[conn_id] = { 'number': 1, 'expected': (conn_id in EXPECTED_CONN_IDS),
                                        'has_expected_attribs': has_expected_attribs(conn_id) }
    return ip_connections

# When pre_filter_function is set, hide_local_traffic is ignored
def get_connection_details_from_pcap_file(filename, pre_filter_function=None,
                                          aft_filter_function=None,
                                          hide_local_traffic=True,
                                          with_rawdata=False,
                                          with_http=False,
                                          rawdata_html_escaped=False,
                                          transform_local_addresses=False,
                                          filter_ip=None):
    pcapreader = PcapReader(filename)
    if pre_filter_function is None:
        if hide_local_traffic:
            packet_list = [p for p in pcapreader if (not is_local_traffic(p)) and (not is_arp_package(p))]
        else:
            packet_list = [p for p in pcapreader if not is_arp_package(p)]
    else:
        packet_list = pre_filter_function(pcapreader)
    ip_connections = []
    for p in packet_list:
        ip_lay = None
        if p.haslayer(scapyIp):
            ip_lay = p.getlayer(scapyIp)
        elif p.haslayer(scapyIpv6):
            ip_lay = p.getlayer(scapyIpv6) 
        conn_type = get_best_known_connection_type(p)
        if ip_lay is not None:
            if (filter_ip is None) or (ip_lay.fields['src'] == filter_ip or ip_lay.fields['dst'] == filter_ip):
                if conn_type == 'TCP':
                    transp_lay = p.getlayer(scapyTcp)
                elif conn_type == 'UDP':
                    transp_lay = p.getlayer(scapyUdp)
                else:
                    transp_lay = None
                if transp_lay is not None:
                    dport = transp_lay.fields['dport']
                    sport = transp_lay.fields['sport']
                else:
                    dport = None
                    sport = None
                if p.haslayer(scapyRaw) and with_rawdata:
                    raw_lay =  p.getlayer(scapyRaw)
                    rawdata = raw_lay.fields['load']
                    if rawdata_html_escaped:
                        rawdata = cgi.escape(rawdata)
                        rawdata = "<br />".join(rawdata.splitlines())
                else:
                    rawdata = None
                if p.haslayer(scapyHTTP) and with_http:
                    http_lay =  p.getlayer(scapyHTTP)
                    http_type = "HTTP"
                    if p.haslayer(scapyHTTPResponse):
                        http_lay = p.getlayer(scapyHTTPResponse)
                        http_type = "HTTPResponse"
                    if p.haslayer(scapyHTTPRequest):
                        http_lay = p.getlayer(scapyHTTPRequest)
                        http_type = "HTTPRequest"
                    http_fields = http_lay.fields
                else:
                    http_fields = None
                    http_type = None
                src = transform_local_address(ip_lay.fields['src']) if transform_local_addresses else ip_lay.fields['src']
                dst = transform_local_address(ip_lay.fields['dst']) if transform_local_addresses else ip_lay.fields['dst']
                curr_ip_conn = ({'timestamp' : p.time,
                                 'conn_type' : conn_type,
                                 'src' :  src,
                                 'dst' : dst,
                                 'sport' : sport,
                                 'dport' : dport,
                                 'rawdata' : rawdata,
                                 'http_fields' : http_fields,
                                 'http_type' : http_type})
                if (aft_filter_function is None) or (aft_filter_function(curr_ip_conn)):
                    ip_connections.append(curr_ip_conn)
    pcapreader.close()
    return ip_connections

def get_dns_ip_domain_relations_from_pcap(pcap_filename):
    res_ip_domain_assoc = dict()
    cname_assoc = dict()
    pcapreader = PcapReader(pcap_filename)
    packet_list = [p for p in pcapreader if p.haslayer(scapyDNSRR)]
    for p in packet_list:
        dnsrr = p[scapyDNSRR]
        while isinstance(dnsrr, scapyDNSRR):
            record_type = dnsrr.fields['type']
            if (record_type == DNS_RR_TYPE['A']) or (record_type == DNS_RR_TYPE['AAAA']):
                ip_addr = dnsrr.fields['rdata']
                domain = dnsrr.fields['rrname']
                if ip_addr not in res_ip_domain_assoc:
                    res_ip_domain_assoc[ip_addr] = set([domain])
                else:
                    res_ip_domain_assoc[ip_addr].add(domain)
            if record_type == DNS_RR_TYPE['CNAME']:
                #print dnsrr.fields
                canonical_name = dnsrr.fields['rdata']
                original_name = dnsrr.fields['rrname']
                if canonical_name not in cname_assoc:
                    cname_assoc[canonical_name] = set([original_name])
                else:
                    cname_assoc[canonical_name].add(original_name)
            dnsrr = dnsrr.payload
    # Merge cname_assoc
    for ip_addr in res_ip_domain_assoc:
        curr_to_merge = set()
        curr_set = res_ip_domain_assoc[ip_addr]
        for canonical_name in curr_set:
            if canonical_name in cname_assoc:
                curr_to_merge = curr_to_merge.union(cname_assoc[canonical_name])
        res_ip_domain_assoc[ip_addr] = curr_set.union(curr_to_merge)
    return res_ip_domain_assoc

def get_all_possible_urls(ip_addr, domains, path):
    possible_urls = [ ip_addr + path ]
    for domain in domains:
        # strip trailing dot of domain
        possible_urls.append(domain[:-1] + path)
    return possible_urls