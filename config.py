#!bin/python
LOGFILE = 'fexml2stix.log'
SAVE_DIRECTORY = "/var/www/fe2stix/output"
PRODUCER_NAME = "Example corporation"
PRODUCER_URL = "http://www.example.com"

# taxii config
TAXII_SERVER = '192.168.0.2'
TAXII_PORT = 9000
TAXII_USER = 'fe2stix'
TAXII_PASS = 'Ple9JhbGciOiJIUzIxxiIsInR5cCI6IkpXVC'
TAXII_COLLECTION = 'fireye-internal'
TAXII_INBOX = '/services/inbox-fe'

# stix config
STIX_BINDING = 'urn:stix.mitre.org:xml:1.1.1'

# fireeye config
CMS_HOSTNAME = "fireeye.cms.example.com"
API_CREDS = ('api_analyst', 'qwrjkl237894klawj3290')
HTML_CREDS = ('api_html_analyst', 'aslnkfsflahk2903fskl')
CMS_MALWARE_PASSWORD = 'infected'

#viper config
VIPER_HOST = 'localhost'
VIPER_PORT = 8080
