# app.py
a simple flash app that 
+ collect FireEye (CMS) produced Extended XML notification 
+ dispatches to fexml2stix.FireEyeXMLParser (STIX)
+ collects the malware object from FireEye Alerts
+ send malware objects to a Viper instance for storage

# fexml2stix.FireEyeXMLParser (inspired from fe2stix https://github.com/BechtelCIRT/fe2stix )
Parses the XML, uses fireeye.* API, translates to STIX, and send to STIX server.

# fireeye.py
a WS API and HTML API to collect additional alerts/reports from the CMS.

# fesubclasses.py, fealerts.py
XML to Python bindings by generateDS.
FireEye (~7.6) alerts XSD to python.

# viperapi.py
Wrapper to push malware file object to a viper instance


# Configuration
Set the variables  in the config.py file

## Configure FireEye Notification
1. Create HTTP Event
2. Add HTTP Server
3. Name it 'fexml2stix'
4. Set the server URL as 'http://youserver.com:5000/api/v1/fe'
5. Notify for all events and deliver per event
6. Leave it as the generic provider
7. Select 'JSON Normal' for the message format
8. Submit a malicious sample, and watch the magic happen

### GPL License

