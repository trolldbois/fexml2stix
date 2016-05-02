#!bin/python

'''
FireEye CMS -> STIX/TAXII
See README
'''

import logging

# Flask imports
from flask import Flask, jsonify, request, make_response

# STIX imports
import stix.utils as utils
from cybox.core import Observable
from cybox.common import Hash
from cybox.objects.address_object import Address
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI
from cybox.objects.api_object import API
from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator
from stix.utils import set_id_namespace
from stix.data_marking import Marking, MarkingSpecification

# General imports
import json
import re
import time

import config
import fexml2stix
import viperapi

# Pull config data
SAVE_DIRECTORY = config.SAVE_DIRECTORY
PRODUCER_NAME = config.PRODUCER_NAME
PRODUCER_URL = config.PRODUCER_URL

log = logging.getLogger("app.py")
app = Flask(__name__)

# FireEye API Route
@app.route('/api/v1/fe', methods=['POST'])
def create_stix_file():

    fe_parser = fexml2stix.FireEyeXMLParser()

    # JSON load the POSTed request data
    try:
        data_recv = request.data
        fexml2stix.write_to_file('request', data_recv)
        log.debug('data_recv len: %d', len(data_recv))
        fe_alerts = fe_parser.parse(data_recv)
    except Exception as e:
        # log error to log file.
        log.error("parsing failed: %s", e)
        return make_response(jsonify({'Error': "Unable to decode xml document %s" % e}), 400)

    # transcode fe XML to STIX
    try:
        stix_worker = fexml2stix.FEXMLtoSTIX()
        for alert in fe_alerts.alert:
            stix_package = stix_worker.transform(alert)
            stix_worker.send_to_taxii(stix_package)
    except Exception as e: 
        # log error to log file.
        log.error(e)
        return make_response(jsonify({'Success': "STIX document successfully generated"}), 200)
        
    # fetch malware archive from CMS
    try:
        viper_worker = viperapi.ViperAPI()
        for alert in fe_alerts.alert:
            md5sum = fe_parser.has_malware_object(alert)
            if md5sum and not viper_worker.has_file(md5sum=md5sum):
                try:
                    for mal_md5, mal_id, filename, zipname in fe_parser.download_malware_objects(alert):
                        if viper_worker.has_file(md5sum=mal_md5):
                            log.info('Viper already has file %s', mal_md5)
                            continue
                        viper_worker.add_file(filename, zipname)
                except IOError as e:
                    log.error('could not download %s out of alert %s', md5sum, alert.id)
        pass
    except Exception as e: 
        # log error to log file.
        log.error(e)
        return make_response(jsonify({'Success': "STIX document successfully generated"}), 200)
    
    # Return success response
    fe_parser.close()
    return make_response(jsonify({'Success': "STIX document successfully generated"}), 200)
    

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    ch = logging.FileHandler(config.LOGFILE)
    ch.setLevel(logging.DEBUG)
    logging.getLogger("root").addHandler(ch)
    logging.getLogger("cabby.client11.Client11").setLevel(logging.INFO)
    app.run(threaded=True, host='0.0.0.0') #, debug=True)

