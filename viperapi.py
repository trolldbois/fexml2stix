#!/bin/sh python

import base64
import json
import time
import logging
import sys
import re
import os
import zipfile

import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

import config

log = logging.getLogger('viperapi')

        
class ViperAPI(object):

    TEST = "/test"
    ADD = "/file/add"
    GET = "/file/get"
    FIND = "/file/find"
    RUN = "/modules/run"

    def __init__(self, _host=config.VIPER_HOST, _port=config.VIPER_PORT, _project='default'):
        self.host = _host
        self.port = _port
        self.project = _project
        # self.validate_ssl = False
        # self.validate_ssl = ('old-chain.pem')
        headers = self._init_headers()
        self._session = requests.Session()
        self._session.headers.update(headers)
        self._write_to_file = True
        
    def _init_headers(self):
        # we do json here
        headers = {"Accept": "application/json"}
        return headers

    def _url(self, uri):
        return "http://%s:%d%s" % (self.host, self.port, uri)

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
        
    def has_file(self, md5sum):
        """ Check if the checksum is in the database. """
        r = self._session.post(self._url(self.FIND), data={'md5': md5sum, 'project': self.project})
        if r.status_code == 400:
            log.error('Request unsuccessful due to invalid search terms for md5: %s', md5sum)
            raise ValueError('get_alert error:400')
        elif r.status_code != 200:
            log.error('Error %d while viper.find', r.status_code)
            raise ValueError('viper.find error:%d' % r.status_code)
        # DEBUG
        self.writeJsonToFile('viper-response-%s' % md5sum, r.content)
        #
        results = r.json()[self.project]
        if len(results) == 0:
            return False
        log.info('Malware object %s already in viper', md5sum)
        return True

    def add_file(self, filename, zipfilename):
        """ Add the file to viper db."""
        # broken right now.
        zfin = zipfile.ZipFile(zipfilename)
        # ERROR:app.py:File is not a zip file
        filename_in_zip = zfin.namelist()[0]
        log.debug("adding file %s", filename)
        #headers = {'content-type': 'application/octet-stream', "Content-Disposition": 'form-data; name="file"; filename="7cc56da012c5cb021f31ee79d09ca1b8.zip"'}
        #r = self._session.post(self._url(self.ADD), headers=headers, data=data)
        #filename = "7cc56da012c5cb021f31ee79d09ca1b8.zip"
        files = {'file': (filename, zfin.open(filename_in_zip, 'r', pwd=config.CMS_MALWARE_PASSWORD).read())}
        #headers = {'content-type': 'multipart/form-data'}
        r = self._session.post(self._url(self.ADD), files=files)
        if r.status_code == 200:
            return True
        else:
            log.error('Something failed while adding file : %s', r.content)
            raise ValueError('add_fileerror:%d %s' %(r.status_code, r.content))
        return True

    
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
 

