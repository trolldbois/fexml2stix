#!/bin/sh python

import base64
import json
import time
import logging
import sys
import re
import os
import xml.etree.ElementTree

import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

import config

import fealerts

log = logging.getLogger('feapi')

# Explanation:
# a) login to the WSAPI and the HTMLAPI
# b) get alerts for the past 24_hours .
# c) the list of alerts are a host summary of the alert, alert type, Fe product , maybe a md5sum or an email address
# d) for each alert, use the HTML API to get a report on them as to get an HTML_Report
#
# Web MPS:
#  domain-infection: little IOC are in HTML_Report in json. But XML 
#  web-infection: the HTML_Report contains all IOC.
#  malware-object: the HTML_Report contains extended metadata on object.
#       + IoC are fetchable using the alert-url HTML_DetailledAlert 
#

class Done(Exception):
    pass

class HTML_DetailledAlert(dict):
    def __init__(self, jsoncontent):
        super(HTML_DetailledAlert, self).__init__(jsoncontent)


class HTML_Report(dict):
    def __init__(self, jsoncontent):
        super(HTML_Report, self).__init__(jsoncontent)

    def get_detailled_alerts(self):
        if isinstance(self["alert"], dict):
            return [HTML_DetailledAlert(self["alert"])]
        elif isinstance(self["alert"], list):
            return [HTML_DetailledAlert(alert) for alert in self["alert"]]


class WS_Alert(dict):
    def __init__(self, jsoncontent):
        super(WS_Alert, self).__init__(jsoncontent)


class WS_Alerts(dict):
    def __init__(self, jsoncontent):
        super(WS_Alerts, self).__init__(jsoncontent)
        
    def get_counts(self):
        return self["alertsCount"]
    
    def get_appliance(self):
        return self["appliance"]
        
    def get_version(self):
        return self["version"]
        
    def get_msg(self):
        return self["msg"]

    def get_alerts(self):
        return [WS_Alert(alert) for alert in self["alert"]]
        
        
class WSAPI(object):

    LOGIN = "/wsapis/v1.0.0/auth/login"
    ALERTS = "/wsapis/v1.0.0/alerts"
    REPORTS = "/wsapis/v1.0.0/reports/report"
    # REPORTS = "/wsapis/v1.0.0/reports/single_alert_details_report"
    LOGOUT = "/wsapis/v1.0.0/auth/logout"

    def __init__(self, host):
        self.host = host
        # self.validate_ssl = False
        self.validate_ssl = ('old-chain.pem')
        self.api_key = None
        headers = self._init_headers()
        self._session = requests.Session()
        self._session.headers.update(headers)
        self._write_to_file = True
        self.logged_in = False
        
    def _init_headers(self):
        # we do json here
        headers = {"X-FeClient-Token": "MISP-Client",
                   "Accept": "application/json"}
        self.__alerts_params = {'duration': '24_hours' } #, 'info_level': 'extended'}
        return headers

    def writeToFile(self, name, ext, content):
        if not self._write_to_file:
            return
        open('%s/%s.%s' % (config.SAVE_DIRECTORY, name, ext), 'wb').write(content)
        log.debug('--->> %s.%s %d bytes', name, ext, len(content))
        return

    def writeJsonToFile(self, name, my_json):
        if not self._write_to_file:
            return
        with open('%s/%s.json' % (config.SAVE_DIRECTORY, name), 'wb') as outfile:
            json.dump(my_json, outfile)
        log.debug('--->> %s.json', name)
        return
        
    def _alerts_params(self):
        return self.__alerts_params

    def login(self, auth):
        base64string = base64.encodestring('%s:%s' % auth).replace('\n', '')
        headers = {'Authorization': 'Basic %s' % base64string}
        r = self._session.post(self._url(self.LOGIN),
                                verify=self.validate_ssl,
                                headers=headers, data="test")
        if r.status_code != 200:
            log.error('Error %d while login', r.status_code)
            log.error(self._url(self.LOGIN))
            log.error(r.request.headers)
            log.error(r.content)
            raise ValueError('authentication error')
        # By default, the session times out after 29 minutes of inactivity or
        # after 100 requests.
        self._session.headers.update({"x-feapi-token": r.headers["x-feapi-token"]})
        self.logged_in = True

    def logout(self):
        r = self._session.post(self._url(self.LOGOUT),
                         verify=self.validate_ssl)
        if "x-feapi-token" in self._session.headers:
            del self._session.headers["x-feapi-token"]
        if r.status_code != 204:
            log.error('WSAPI Logout die silently on code %d', r.status_code)
            log.error(r.content)
        return

    def handle_unlog(self):
        self.logged_in = False
        
    def _url(self, uri):
        return 'https://%s%s?' % (self.host, uri)

    def get_alerts(self):
        """
        Return the list of alerts in json format
        """
        r = self._session.get(self._url(self.ALERTS),
                         params=self._alerts_params(),
                         verify=self.validate_ssl)
        if r.status_code == 400:
            log.error('Request unsuccessful due to invalid filter values.')
            raise ValueError('get_alert error:400')
        elif r.status_code != 200:
            log.error('Error %d while get_alerts', r.status_code)
            raise ValueError('get_alert error:%d' % r.status_code)
        # DEBUG
        self.writeToFile('alerts', 'json', r.content)
        return WS_Alerts(r.json())

    def get_alert(self, alert_id):
        """
        Return the alert in json format
        """
        params = {'alert_id': alert_id } #,'info_level': 'normal'}
        r = self._session.get(self._url(self.ALERTS),
                         params=params,
                         verify=self.validate_ssl)
        if r.status_code == 400:
            log.error('Request unsuccessful due to invalid filter values.')
            raise ValueError('get_alert error:400')
        elif r.status_code != 200:
            log.error('Error %d while get_alerts', r.status_code)
            raise ValueError('get_alert error:%d' % r.status_code)
        # DEBUG
        self.writeToFile('alert', 'json', r.content)
        return WS_Alerts(r.json())

    def get_report(self, alert_id, alert_name):
        """
        returns a PDF
        """
        outname = '%s_PDF_Report' % alert_id
        # report_type=alertDetailsReport&infection_id=8351&infection_type=malware-object
        # FIXME find a type=json parameter
        params = {'report_type': 'alertDetailsReport',
                  'infection_id': alert_id,
                  'infection_type': alert_name}
        r = self._session.get(self._url(self.REPORTS),
                         params=params,
                         verify=self.validate_ssl)
        if r.status_code == 400:
            log.error('Request unsuccessful due to invalid filter values.')
            raise ValueError('get_report error:400')
        elif r.status_code != 200:
            log.error('Error %d while get_alerts', r.status_code)
            raise ValueError('get_report error:%d' % r.status_code)
        self.writeToFile(outname, 'pdf', r.content)
        return r

class HTMLAPI(WSAPI):

    LOGIN = '/login/login'
    LOGOUT = '/login/logout'
    IOC_REPORT = '/report/single_alert_details_report'
    IOC_REPORT2 = '/event_stream/events_in_xml'
    # 404 IOC_REPORT3 = '/event_stream/events_in_json'
    EVENTS_FOR_BOT = '/event_stream/events_for_bot'
    WEB_ALERT = '/event_stream/events_for_bot'
    EMPS_ALERT = '/emps/eanalysis'
    # MALWARE = '/botnets/send_binary'
    # https://mtllamon001.ca.aero.bombardier.net/event_stream/send_zip_file?zip_path=done/259e882d0ffafab3437390ec7203f54d.zip
    MALWARE = '/event_stream/send_zip_file'

    def _init_headers(self):
        # we do json here
        headers = { "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
        self.__alerts_params = {'duration': '24_hours'}
        return headers

    def login(self, auth):
        """
        Login in html
        """
        r = self._session.get(self._url(self.LOGIN),
                              verify=self.validate_ssl)
        if r.status_code != 200:
            raise ValueError(r.status_code)
        token = re.search(r'''<input name="authenticity_token" type="hidden" value="([^"]+)" />''', r.content).groups()[0]
        params = {'utf8': '%E2%9C%93',
                  'authenticity_token': token,
                  'user[account]': auth[0],
                  'user[password]': auth[1],
                  'window_size': '1760x507'}
        
        r = self._session.post(self._url(self.LOGIN),
                                verify=self.validate_ssl,
                                params=params)                                
        if r.status_code != 200:
            log.error('Error %d while login', r.status_code)
            raise ValueError('authentication error')
        # cookies are updated
        self.logged_in = True
        return

    def logout(self):
        params = {'user_initiated': 1}
        r = self._session.get(self._url(self.LOGOUT),
                                params = params,
                              verify=self.validate_ssl)
        # cookies are updated
        self.logged_in = False
        if r.status_code != 200:
            log.error('WEBAPI Logout die silently on code %d', r.status_code)
        return
        
    def see_alert(self, alert_id):
        """ Unused """
        r = self._session.get(self._url(self.ALERT),
                         params={'inc_id': alert_id},
                         verify=self.validate_ssl)
        return r

    def get_report(self, alert_id, alert_name, fmt='json'):
        """
        returns json format of the alert.
        """
        outname = '%s_HTML_Report' % alert_id
        #if os.access(outname, os.F_OK):
        #    raise Done
        # report_type=alertDetailsReport&infection_id=8351&infection_type=malware-object
        # FE 6
        params = {'report_type': 'common/Alert_Details',
                  'Alert_Details_alert_type': alert_name,
                  'Alert_Details_report_detail': 'extended',
                  'Alert_Details_report_format': fmt,
                  'inf_id': alert_id}
        # FE 7.7.1
        params = {'report_type': 'alert_details',
                  'alert_type': alert_name,
                  'report_detail': 'extended',
                  'report_format': fmt,
                  'inf_id': alert_id}

        r = self._session.get(self._url(self.IOC_REPORT),
                         params=params,
                         verify=self.validate_ssl)
        if r.status_code == 400:
            log.error('Request unsuccessful due to invalid filter values.')
            raise ValueError('get_report error:400')
        elif r.status_code != 200:
            log.error('Error %d while get_alerts', r.status_code)
            raise ValueError('get_report error:%d' % r.status_code)
        # print r.request.__dict__
        if len(r.history) == 2:
            raise ValueError('get_report error redirected to logout:%d' % r.status_code)
        self.writeToFile(outname, fmt, r.content)
        if 'json' == fmt:
            return HTML_Report(r.json())
        else:
            return r.content
            
    def get_malware_object_analysis_id(self, alert_id, alert_url, product):
        # regex works for both 
        ## analysis_id_url = alert['alert-url']
        ## product = alert['product']
        param_name, analysis_id = re.search(r'''\?(.+_id)=(\d+)''', alert_url).groups()
        # url is different for emps and web
        log.debug("get_malware_object_analysis_id %s %s", product, analysis_id)
        if product == "Web MPS" or product == "WEB_MPS":
            #params = { 'inc_id': analysis_id}
            params = { '%s_id'%(param_name): analysis_id}
            url = self.WEB_ALERT
        elif product == "Email MPS" or product == "EMAIL_MPS":
            params = { 'e_id': analysis_id}
            url = self.EMPS_ALERT
        else:
            log.error("Unknown product: %s", product)
            raise TypeError("unknown product: %s" % product)
        # do the request
        r = self._session.get(self._url(url),
                         params=params,
                         verify=self.validate_ssl)
        if r.status_code == 400:
            log.error('Request unsuccessful due to invalid filter values.')
            raise ValueError('get_report error:400')
        elif r.status_code != 200:
            log.error('Error %d while get_alerts', r.status_code)
            raise ValueError('get_report error:%d' % r.status_code)
        
        # DEBUG
        self.writeToFile(alert_id, 'eanalysis', r.content)
        tokens = re.findall(r'''render_event_cluster\(&#x27;([,\s\d]+)&#x27;,\s+([\d]+),''', r.content)
        print tokens
        # render_event_cluster("event_id"; alert_id ....)
        # token = re.search(r'''render_event_cluster\(&#x27;([,\s\d]+)&#x27;,\s%s''' % alert_id, r.content).groups()[0]
        # return token
        return tokens


    def get_full_report(self, events_id, alert_id):
        """This URI returns an XML description of the alert."""
        # if ba_path=="", then its this alert_id is not the root alert_id. Its probably a signature match.
        # malware object can not be downloaded here. We need to query the original root alert id.
        #
        #<?xml version="1.0" encoding="utf-8"?>
        #<events cms="y">
        #<malware_analysis id="95980188" analysis_type="Sandbox" prefetch="0" l7proto="9" ft="ace" ba_name="4e18a932960324ba9dbafd4ebcf64cef
        #.zip" ba_path="done/4e18a932960324ba9dbafd4ebcf64cef.zip">
        #</malware_analysis>

        #curl 'https://mtllamon001.ca.aero.bombardier.net/event_stream/events_in_xml?events=1193512&arow=626364750&noxsl=y'
        outname = '%s_HTML_FullReport' % alert_id
        #if os.access(outname, os.F_OK):
        #    return 
        params = { 'events': events_id, 
                   'arow': alert_id,
                   'noxsl': 'y' }
        r = self._session.get(self._url(self.IOC_REPORT2),
                         params=params,
                         verify=self.validate_ssl)
        if r.status_code == 400:
            log.error('Request unsuccessful due to invalid filter values.')
            raise ValueError('get_report error:400')
        elif r.status_code != 200:
            log.error('Error %d while get_alerts', r.status_code)
            raise ValueError('get_report error:%d' % r.status_code)
        # DEBUG
        self.writeToFile(outname, 'xml', r.content)
        # parse XML 
        tree = xml.etree.ElementTree.fromstring(r.content)
        return tree
        
    def get_malware_file(self, checksum_name):
        # ?mal_id=64053022
        # ?zip_path=done/259e882d0ffafab3437390ec7203f54d.zip
        # outname = '%s_%s' % (alert_id, checksum_name)
        # params = { 'mal_id': alert_id}
        ####
        # https://mtllamon001.ca.aero.bombardier.net/botnets/send_binary?mal_id=95726124
        # https://mtllamon001.ca.aero.bombardier.net/event_stream/send_zip_file?zip_path=done/7cc56da012c5cb021f31ee79d09ca1b8.zip
        #
        # apparently, a prep query need to happen before send_zip_file.
        # curl 'https://mtllamon001.ca.aero.bombardier.net/event_stream/events_for_bot?ma_id=96155900&ati_details_id=&know_attack=Malware.Binary.doc' -H 'Host: mtllamon001.ca.aero.bombardier.net' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.7,fr;q=0.3' -H 'Accept-Encoding: gzip, deflate' -H 'DNT: 1' -H 'Referer: https://mtllamon001.ca.aero.bombardier.net/emps/alerts' -H 'Cookie: erJOJPQYCFBMNUJDDYWOH5TOSC6Q2=PWD=&HMS=MTLWAERMC006&LGN=IIYDKMZRHEZDQ; _session_id=d2d18252b5ba9fdea6b65f611b58ff1f; BALANCEID=balancer.thin2; chkcookie=1450112616223; WSMD=IEV%2F%2FIk%2BKCcE9O0lXqfL2HnrOdNkO64nQ%2Fl2fG7WwQKdAwo%3D' -H 'Connection: keep-alive'
        #
        outname = checksum_name
        params = { 'zip_path': 'done/%s.zip' % checksum_name}
        log.debug('URI: %s', self._url(self.MALWARE))
        log.debug('params: %s', params)
        r = self._session.get(self._url(self.MALWARE),
                         params=params,
                         verify=self.validate_ssl)
        if r.status_code == 400:
            log.error('get_malware_file error code 400: %s', checksum_name)
            raise ValueError('get_report error:400')
        elif r.status_code != 200:
            log.error('Error %d while get_malware_file: %s', r.status_code, checksum_name)
            raise ValueError('get_report error:%d' % r.status_code)
        # DEBUG
        self.writeToFile(outname, 'zip', r.content)
        return r.content
        
def json_to_py_name(alert):
    name = alert['name']
    name = name.lower().replace('_', '-')
    return name

def ts2time(ts):
    return time.ctime(ts/1000)

def run(alert_id=None):

    api = WSAPI(config.CMS_HOSTNAME)
    api.login(config.API_CREDS)
    
    htmlapi = HTMLAPI(config.CMS_HOSTNAME)
    htmlapi.login(config.HTML_CREDS)

    try:
        if alert_id is not None:
            alerts = api.get_alert(int(alert_id))
        else:
            alerts = api.get_alerts()
        for alert in alerts.get_alerts():
            log.debug("%s %s %s %s %s", alert['product'], alert['sensor'], alert['name'], ts2time(alert['occurred']), alert['id'])
            print alert.keys()
            malwares_info = handle_one_alert(api, htmlapi, alert['id'], json_to_py_name(alert))
            for _ in post_handle_one_alert(htmlapi, alert_id, malwares_info):
                pass
    finally:
        api.logout()
        htmlapi.logout()
    return
        
def handle_one_alert(api, htmlapi, alert_id, alert_name):
    # the report show detailed information about the malware payload but no IOC
    try:
        # get XML for no reason.
        ## htmlapi.get_report(alert_id, alert_name, 'xml')
        # get json
        report = htmlapi.get_report(alert_id, alert_name)
        # their could be more that one alerts
        html_alerts = report.get_detailled_alerts()
        #print html_alerts
        results = []
        for alert in html_alerts:
            results.extend(get_malware_object_download_links(htmlapi, alert_id, alert_name, alert['alert-url'], alert['product']))
        return results
    except Done:
        return     

def post_handle_one_alert(htmlapi, alert_id, malwares_info):        
    for malware_info in malwares_info:
        mal_id = malware_info['id']
        mal_uri = malware_info['ba_path']
        mal_md5 = malware_info['ba_name'][:-4]
        mal_filename = ''
        log.debug('looking at alert:%s md5:%s URI:%s', mal_id, mal_uri, mal_md5)
        if mal_uri == '':
            log.warning('No URI for %s/%s', mal_id, mal_md5)
            continue
        malware_zip = htmlapi.get_malware_file(mal_md5)
        if malware_zip[:2] != 'PK':
            log.error('Not a zip file. alert:%s md5:%s URI:%s', mal_id, mal_uri, mal_md5)
            yield False, mal_id, mal_md5, None
        # we need to get the real name.
        #if alert_id != mal_id:
        #    report = htmlapi.get_report(alert_id, alert_name)
        #    html_alerts = report.get_detailled_alerts()
        #    for alert in html_alerts:
        yield True, mal_id, mal_md5, malware_zip
        
def get_malware_object_download_links(htmlapi, alert_id, alert_name, alert_url, alert_product):
    res = []
    if alert_name == 'domain-match':
        # we can shortcut as event_id is alert Id ?
        tree = htmlapi.get_full_report(alert_id, alert_id)
        attribs = get_malware_object_analysis_attributes(tree)
        res.append(attribs)
    else:
        # we need analysis ID from the events_from_bot page
        # multiple results
        for events_id, my_alert_id in htmlapi.get_malware_object_analysis_id(alert_id, alert_url, alert_product):
            tree = htmlapi.get_full_report(events_id, my_alert_id)
            attribs = get_malware_object_analysis_attributes(tree)
            # get malware-object file
            res.append(attribs)
    return res

def get_malware_object_analysis_attributes(xml_full_report_tree):
    """ attrib['id'] attrib['ba_path'] attrib['ba_name'] """
    for analysis in xml_full_report_tree.iter('malware_analysis'):
        log.debug(analysis.attrib)
        if analysis.attrib['ba_path'] != '':
            log.debug('Malware-object is at %s', analysis.attrib['ba_path'])
        else:
            log.debug('No Malware-object archive.')
        return analysis.attrib
    

    
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    #root = logging.getLogger()
    #root.setLevel(logging.DEBUG)
    #
    #ch = logging.StreamHandler(sys.stdout)
    #ch.setLevel(logging.DEBUG)
    #log.setLevel(logging.DEBUG)
    #formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    #ch.setFormatter(formatter)
    #root.addHandler(ch)
    # run()
    #test()
    #brute()
    #get_simple(32376)
    if len(sys.argv) == 2:
        run(sys.argv[1])
    else:
        run()
        

