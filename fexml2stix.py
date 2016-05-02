#!/bin/sh python

import base64
import fnmatch
import json
import time
import logging
import sys
import re
import os

log = logging.getLogger('fexml2stix')

# https://cybox.mitre.org/language/version2.1/

# TODO keep HTMLAPI session in app? check logout redirects.
# TODO infection-match use alerts.alert.dst.ip 

# STIX imports
import stix.utils as utils
from cybox.core import Observable
from cybox.common import Hash
from stix.common.vocabs import IndicatorType_1_1
from cybox.objects.address_object import Address
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI
from cybox.objects.api_object import API
from cybox.objects.win_registry_key_object import WinRegistryKey
from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator
#from stix.utils import set_id_namespace
from stix.data_marking import Marking, MarkingSpecification
from cybox.objects.email_message_object import EmailMessage, EmailHeader

import fealerts
import fireeye
import cabby
import viperapi

# get config
import config

class PackageBuilder(object):
    def __init__(self, alert):
    
        self.__urls = set()
        self.__domains = set()
        self.__ipv4 = set()
        self.__hashes = set()
        self.__regkeys = set()
        self.__files = set()
        self.__emails = set()

        PRODUCER_NAME = alert.product
        
        # Domains
        domain_indicator = Indicator()
        domain_indicator.title = "Malware Artifacts - Domain"
        domain_indicator.type = "Malware Artifacts"
        domain_indicator.description = ("Domains derived from sandboxed malware sample.  AlertID: %d" % alert.id)
        domain_indicator.short_description = ("Domains from %d" % alert.id)
        domain_indicator.set_producer_identity(PRODUCER_NAME)
        domain_indicator.set_produced_time(utils.dates.now())
        domain_indicator.indicator_types.append(IndicatorType_1_1.TERM_DOMAIN_WATCHLIST)
        self.domain_indicator = domain_indicator

        # IPs
        ip_indicator = Indicator()
        ip_indicator.title = "Malware Artifacts - IP"
        ip_indicator.description = ("IPs derived from sandboxed malware sample. AlertID: %d" % alert.id)
        ip_indicator.short_description = ("IPs from %d" % alert.id)
        ip_indicator.set_producer_identity(PRODUCER_NAME)
        ip_indicator.set_produced_time(utils.dates.now())
        ip_indicator.indicator_types.append(IndicatorType_1_1.TERM_IP_WATCHLIST)
        self.ip_indicator = ip_indicator

        # URLs
        url_indicator = Indicator()
        url_indicator.title = "Malware Artifacts - URL"
        url_indicator.description = ("URLs derived from sandboxed malware sample. AlertID: %d" % alert.id)
        url_indicator.short_description = ("URLs from %d" % alert.id)
        url_indicator.set_producer_identity(PRODUCER_NAME)
        url_indicator.set_produced_time(utils.dates.now())
        url_indicator.indicator_types.append(IndicatorType_1_1.TERM_URL_WATCHLIST)
        self.url_indicator = url_indicator

        # Hashs
        hash_indicator = Indicator()
        hash_indicator.title = "Malware Artifacts - Files"
        hash_indicator.description = ("Files  derived from sandboxed malware sample. AlertID: %d" % alert.id)
        hash_indicator.short_description = ("File from %d" % alert.id)
        hash_indicator.set_producer_identity(PRODUCER_NAME)
        hash_indicator.set_produced_time(utils.dates.now())
        hash_indicator.indicator_types.append(IndicatorType_1_1.TERM_FILE_HASH_WATCHLIST)
        self.hash_indicator = hash_indicator

        # Registry
        reg_indicator = Indicator()
        reg_indicator.title = "Malware Artifacts - Registry entries"
        reg_indicator.description = ("File hashes derived from sandboxed malware sample. AlertID: %d" % alert.id)
        reg_indicator.short_description = ("Registry entries from %d" % alert.id)
        reg_indicator.set_producer_identity(PRODUCER_NAME)
        reg_indicator.set_produced_time(utils.dates.now())
        reg_indicator.indicator_types.append(IndicatorType_1_1.TERM_MALWARE_ARTIFACTS)
        self.reg_indicator = reg_indicator

        # email_indicator
        email_indicator = Indicator()
        email_indicator.title = "Malware Artifacts - Malicious "
        email_indicator.description = ("Email headers. AlertID: %d" % alert.id)
        email_indicator.short_description = ("Email headers from %d" % alert.id)
        email_indicator.set_producer_identity(PRODUCER_NAME)
        email_indicator.set_produced_time(utils.dates.now())
        email_indicator.indicator_types.append(IndicatorType_1_1.TERM_MALICIOUS_EMAIL )
        self.email_indicator = email_indicator
        
        # Create a STIX Package
        self.stix_package = STIXPackage()

        # Create the STIX Header and add a description.
        stix_header = STIXHeader({"Indicators - Malware Artifacts"})
        stix_header.description = "FireEye Sample ID %d" % alert.id
        self.stix_package.stix_header = stix_header    
        
    def add_ipv4_observable(self, ipv4_address):
        if ipv4_address in self.__ipv4:
            return
        self.__ipv4.add(ipv4_address)
        ipv4_object = Address.from_dict({'address_value': ipv4_address, 'category': Address.CAT_IPV4})
        ipv4_observable = Observable(ipv4_object)
        ipv4_observable.title = "Malware Artifact - IP"
        ipv4_observable.description = "IP derived from sandboxed malware sample."
        ipv4_observable.short_description = "IP from malware."
        self.ip_indicator.add_observable(ipv4_observable)

    def add_domain_name_observable(self, domain_name):
        if domain_name in self.__domains:
            return
        self.__domains.add(domain_name)
        domain_name_object = URI.from_dict({'value': domain_name, 'type': URI.TYPE_DOMAIN})
        domain_name_observable = Observable(domain_name_object)
        domain_name_observable.title = "Malware Artifact - Domain"
        domain_name_observable.description = "Domain derived from sandboxed malware sample."
        domain_name_observable.short_description = "Domain from malware."
        self.domain_indicator.add_observable(domain_name_observable)


    def __add_dns_query_observable(self, qname, qtype, qclass):
        dns_query_object = DNSQuery.from_dict({'value': dns_query, 'type': URI.TYPE_DOMAIN})
        dns_query_observable = Observable(dns_query_object)
        dns_query_observable.title = "Malware Artifact - DNS query"
        dns_query_observable.description = "DNS query derived from sandboxed malware sample."
        dns_query_observable.short_description = "DNS query from malware."
        # FIXME TODO

    def add_file_dropped_observable(self, filename):
        if filename in self.__files:
            return
        self.__files.add(filename)
        #hash_ = Hash(hash_value)
        file_ = File()
        file_.file_name = filename
        #file_.add_hash(hash_)
        file_observable = Observable(file_)
        file_observable.title = "Malware Artifact - File Dropped"
        file_observable.description = "File Dropped derived from sandboxed malware sample."
        file_observable.short_description = "File Dropped from malware."
        self.hash_indicator.add_observable(file_observable)
        
    def add_file_hash_observable(self, filename, md5_value, sha1_value):
        if (filename, md5_value, sha1_value) in self.__hashes:
            return
        self.__hashes.add((filename, md5_value, sha1_value))
        file_ = File()
        file_.file_name = filename
        file_.add_hash(Hash(md5_value))
        file_.add_hash(Hash(sha1_value))
        file_observable = Observable(file_)
        file_observable.title = "Malware Artifact - File Hash"
        file_observable.description = "File hash derived from sandboxed malware sample."
        file_observable.short_description = "File hash from malware."
        self.hash_indicator.add_observable(file_observable)

    def add_url_observable(self, url):
        if url in self.__urls:
            return
        self.__urls.add(url)
        url_object = URI.from_dict({'value': url, 'type': URI.TYPE_URL})
        url_observable = Observable(url_object)
        url_observable.title = "Malware Artifact - URL"
        url_observable.description = "URL derived from sandboxed malware sample."
        url_observable.short_description = "URL from malware."
        self.url_indicator.add_observable(url_observable)

    def add_registry_observable(self, mode, value):
        if (mode, value) in self.__regkeys:
            return
        self.__regkeys.add((mode, value))
        # FIXME value is not parse properly
        _key = '\\'.join(value.split('\\')[3:])
        hive = value.split('\\')[2]
        reg_object = WinRegistryKey.from_dict({'key': _key, 'hive': hive})
        reg_observable = Observable(reg_object)
        reg_observable.title = "Malware Artifact - Registry"
        reg_observable.description = "Registry access derived from sandboxed malware sample."
        reg_observable.short_description = "Registry access from malware."
        self.reg_indicator.add_observable(reg_observable)
    
    def add_email_observable(self, headers):
        e = EmailMessage()
        h = EmailHeader.from_dict(headers)
        e.header = h
        self.__emails.add(e)
        email_observable = Observable(e)
        self.email_indicator.add_observable(email_observable)
        
    def finalize(self):
        # Add those to the package
        if len(self.__domains) > 0:
            self.stix_package.add(self.domain_indicator)
        if len(self.__ipv4) > 0:
            self.stix_package.add(self.ip_indicator)
        if len(self.__urls) > 0:
            self.stix_package.add(self.url_indicator)
        if len(self.__hashes) > 0:
            self.stix_package.add(self.hash_indicator)
        if len(self.__regkeys) > 0:
            self.stix_package.add(self.reg_indicator)
        if len(self.__emails) > 0:
            self.stix_package.add(self.email_indicator)
    



def write_to_file(foutname, data):
    log.debug('write_to_file %s', foutname)
    foutname = os.path.sep.join([config.SAVE_DIRECTORY, foutname])
    f = open(foutname, 'wb')
    f.write(data)
    f.close()
    log.info('Wrote file %s', foutname)
    return foutname
    

class FireEyeXMLParser(object):

    FE_ALERT_FILE_FMT = "%s.fe_alert.xml"

    def __init__(self):
        self.htmlapi = fireeye.HTMLAPI(config.CMS_HOSTNAME)
        self.htmlapi.login(config.HTML_CREDS)
        log.debug('HTML API initialised')
        self.api = fireeye.WSAPI(config.CMS_HOSTNAME)
        try:
            self.api.login(config.API_CREDS)
        except ValueError as e:
            self.htmlapi.logout()
            self.api.logout()
            raise e
        log.debug('WSAPI initialised')
    
    def close(self):
        self.htmlapi.logout()
        self.api.logout()
    
    def parse(self, data):
        # save the input
        try:
            _id = re.search(' id="(\d+)" ', data[:1000]).groups()[0]
        except AttributeError:
            _id = 'latest_error'
        log.debug('Alert ID is %s', _id)
        write_to_file( self.FE_ALERT_FILE_FMT % _id, data)
        # parse the XML to python objects
        alerts = fealerts.parseString(data, silence=True)
        log.debug('%d alerts received', len(alerts.alert))
        return alerts

    def has_malware_object(self, alert):
        for malware in alert.explanation.malware_detected.malware:
            if malware.md5sum:
                return malware.md5sum
        return False

    def download_malware_objects(self, alert):
        # if malware-object then try to download
        for malware in alert.explanation.malware_detected.malware:
            if malware.md5sum:
                # dl a copy
                # we need to load the alert page before getting the malware archive file.
                # /wsapis/v1.0.0/auth/login
                # /login/login
                # /wsapis/v1.0.0/alerts?alert_id=
                # /report/single_alert_details_report
                # /emps/eanalysis?e_id=
                # /event_stream/events_in_xml?noxsl=y&events=
                # /event_stream/send_zip_file?
                #if not self.htmlapi.logged_in:
                #    self.htmlapi.login(config.HTML_CREDS)
                # zip_data = self.htmlapi.get_malware_file(malware.md5sum)
                #if zip_data[:2] != 'PK':
                #    raise IOError('Data returned is not a Zip File')
                # Human CMS says : event_in_xml with param events=1882143
                # versus Automation went for events_in_xml events=1882152
                ##
                malwares_info = fireeye.handle_one_alert(self.api, self.htmlapi, alert.id, alert.name)
                for res, mal_id, mal_md5, zip_data in fireeye.post_handle_one_alert(self.htmlapi, alert.id, malwares_info):
                    if not res:
                        continue
                    # duplicate with htmlapi debug writetofile.
                    #zip_filename = write_to_file( '%s.zip' % malware.md5sum, zip_data)
                    zip_filename = os.path.sep.join([config.SAVE_DIRECTORY, mal_md5 +'.zip'])
                    # original name and zip filename
                    yield mal_md5, mal_id, malware.original, zip_filename
        raise StopIteration
        

class FEXMLtoSTIX(object):
    STIX_FILE_FMT = "%d.stix.xml"

    def __init__(self):
        self.cabby = cabby.create_client( config.TAXII_SERVER, config.TAXII_PORT, discovery_path='/services/discovery-internal', version='1.1')
        # self.cabby.set_proxy(self.cabby.NO_PROXY)
        self.cabby.set_auth(username=config.TAXII_USER, password=config.TAXII_PASS, jwt_auth_url='/management/auth')
        pass

    def transform(self, alert):
        # create the STIX package
        pack = PackageBuilder(alert)
        # parse the explanation DOM
        if alert.explanation:
            if alert.explanation.malware_detected:
                self.parse_malware_detected(pack, alert)
            if alert.explanation.os_changes:
                self.parse_os_changes(pack, alert)
        # if EX
        if alert.smtp_message:
            self.parse_smtp_message(pack, alert)
        # more ip 
        if alert.name == "infection-match":
            self.parse_dst_ip(pack, alert)
        #
        pack.finalize()
        # save to file
        write_to_file( self.STIX_FILE_FMT % alert.id, pack.stix_package.to_xml())
        return pack

    def send_to_taxii(self, _pack):
        # push to TAXII
        self.cabby.push(_pack.stix_package.to_xml(), config.STIX_BINDING, collection_names=[config.TAXII_COLLECTION], uri=config.TAXII_INBOX)
        
    def parse_dst_ip(self, pack, alert):
        if alert.dst:
            if alert.dst.ip:
                pack.add_ipv4_observable(alert.dst.ip)
        return
        
    def parse_smtp_message(self, pack, alert):
        headers = {}
        headers['message_id']= alert.smtp_message.id
        headers['from_'] = alert.src.smtp_mail_from
        headers['subject'] = alert.smtp_message.subject
        # more headers parsing
        # get the source server
        line = alert.smtp_message.smtp_header.split('Received')[2]
        server_ip = re.search('\[(\d+\.\d+\.\d+\.\d+)\]', line)
        if server_ip:
            server_ip = server_ip.groups()[0]
            headers['x_originating_ip'] = server_ip
        # 
        lines = alert.smtp_message.smtp_header.lower().split('\r\n')
        # get the sender name
        for l in lines:
            if l.startswith('from:'):
                headers['sender'] = html.fromstring(l).text[5:].lower()
            elif l.startswith('reply-to:'):
                headers['reply_to'] = html.fromstring(l).text[9:].lower()
            elif l.startswith('user-agent:'):
                headers['user_agent'] = html.fromstring(l).text[11:].lower()
            elif l.startswith('x-mailer:'):
                headers['x_mailer'] = html.fromstring(l).text[9:].lower()
        # pack it
        pack.add_email_observable(headers)
        return
                
    def parse_malware_detected(self, pack, alert):
        # if malware-object then try to download
        for malware in alert.explanation.malware_detected.malware:
            if malware.md5sum:
                # cybox it
                pack.add_file_hash_observable(malware.original, malware.md5sum, None)
                # dl a copy
                #if not self.htmlapi.logged_in:
                #    self.htmlapi.login(config.HTML_CREDS)
                #zip_data = self.htmlapi.get_malware_file(malware.md5sum)
                #self.write_to_file( '%s.zip' % malware.md5sum, zip_data)
                # todo unzip and calculate sha1
        return
        
    def parse_os_changes(self, pack, alert):
        # List of indicators to be deduped
        hostnames = []
        ips = []
        urls = []
        md5s = []
        sha1s = []
        registries = []

        for os_change in alert.explanation.os_changes:
            # dropped files
            for entry in os_change.file:
                # print entry.__dict__
                # <file mode="created" timestamp="9148" type="dropped_executable">
                if entry.mode == 'created':
                    # @type is renamed @type_
                    if entry.type_ in ['dropped_executable','dropped_batch']:
                        pack.add_file_dropped_observable(entry.value)
                    else:
                        print 'file entry type unknown', entry.type_
                elif entry.mode == 'close':
                    # @type is renamed @type_
                    pack.add_file_hash_observable(entry.value, entry.md5sum, entry.sha1sum)
            # registry entries
            for entry in os_change.regkey:
                pack.add_registry_observable(entry.mode, entry.value)
            # network indicators 
            if os_change.network:
                for entry in os_change.network:
                    # mode
                    #  processinfo
                    #  protocol_type
                    #  destination_port
                    #  listen_port
                    #  ipaddress
                    #  qtype
                    #  hostname
                    #  winsock_res
                    #  dns_response_code
                    if entry.mode == "dns_query":
                        # FIXME DNS_query
                        pack.add_domain_name_observable(entry.hostname)
                    elif entry.mode == "dns_query_answer":
                        # FIXME DNS_query
                        pack.add_domain_name_observable(entry.hostname)
                    elif entry.mode == "http_request":
                        domain = re.search('~~Host:\s(.*?)~~', entry.http_request)
                        url = re.search('^.*\s(.*?)\sHTTP', entry.http_request)
                        if domain:
                            domain_name = domain.group(1)
                        if url:
                            url_string = url.group(1)
                        pack.add_url_observable(domain_name + url_string)
                    else:
                        print 'unhandled network mode', entry.mode
                    # ignore ip address from FE address space
                    if entry.ipaddress and not entry.ipaddress.startswith('199.16.19'):
                        pack.add_ipv4_observable(entry.ipaddress)

                    # Add indicators for files
                    if entry.processinfo and entry.processinfo.md5sum:
                        filename = re.search('([\w-]+\..*)', entry.processinfo.imagepath)
                        if filename:
                            pack.add_file_hash_observable(filename.group(1), entry.processinfo.md5sum, None)
            # process indicators
            if os_change.process:
                for entry in os_change.process:
                    pack.add_file_hash_observable(entry.value, entry.md5sum, entry.sha1sum)
            

def run_single_alert(fname, fe_parser=None):
    if fe_parser is None:
        fe_parser = FireEyeXMLParser()
    with open(os.path.sep.join([config.SAVE_DIRECTORY,fname]), 'rb') as fin:
        fe_alerts = fe_parser.parse(fin.read())
        #stix_worker = FEXMLtoSTIX()
        #for alert in fe_alerts.alert:
        #    stix_package = stix_worker.transform(alert)
        #    # dont send stix_worker.send_to_taxii(stix_package)        
        # fetch malware archive from CMS
        viper_worker = viperapi.ViperAPI()
        for alert in fe_alerts.alert:
            md5sum = fe_parser.has_malware_object(alert)
            if md5sum and not viper_worker.has_file(md5sum=md5sum):
                try:
                    for mal_md5, mal_id, filename, zipname in fe_parser.download_malware_objects(alert):
                        if viper_worker.has_file(md5sum=mal_md5):
                            log.info('Viper already has file ', mal_md5)
                            continue
                        viper_worker.add_file(filename, zipname)
                except IOError as e:
                    log.error('could not download %s out of alert %s', md5sum, alert.id)
        pass

def run_all_alerts():
    # force reload all malware object
    fe_parser = FireEyeXMLParser()
    try:
        for fname in os.listdir(config.SAVE_DIRECTORY):
            if not fnmatch.fnmatch(fname, '96*.fe_alert.xml'):
                continue
            log.info('reading filename %s', fname)
            # else try do viper the malware object
            run_single_alert(fname, fe_parser)
        return
    finally:
        fe_parser.close()
        
    
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("cabby.client11.Client11").setLevel(logging.INFO)
    #fname = '1211441_HTML_Report.xml'
    #fname = '63567807_HTML_Report.xml'
    #fname = '63820920.xml'
    
    if len(sys.argv) == 2:
        fname = sys.argv[1]
        run_single_alert(fname)
    else:
        run_all_alerts()
