#!/usr/bin/env python

#
# Generated Tue Aug  4 15:52:40 2015 by generateDS.py version 2.16a.
#
# Command line options:
#   ('-f', '')
#   ('-o', 'fealerts.py')
#   ('-s', 'fesubclasses.py')
#   ('--super', 'fealerts')
#
# Command line arguments:
#   FireEyeAlertSchema.xsd
#
# Command line:
#   /home/user/Projects/MISP/fexml2stix/bin/generateDS.py -f -o "fealerts.py" -s "fesubclasses.py" --super="fealerts" FireEyeAlertSchema.xsd
#
# Current working directory (os.getcwd()):
#   fexml
#

import sys
from lxml import etree as etree_

import fealerts as supermod

def parsexml_(infile, parser=None, **kwargs):
    if parser is None:
        # Use the lxml ElementTree compatible parser so that, e.g.,
        #   we ignore comments.
        parser = etree_.ETCompatXMLParser()
    doc = etree_.parse(infile, parser=parser, **kwargs)
    return doc

#
# Globals
#

ExternalEncoding = 'ascii'

#
# Data representation classes
#


class alertsSub(supermod.alerts):
    def __init__(self, msg=None, product=None, version=None, appliance=None, appliance_id=None, alert=None):
        super(alertsSub, self).__init__(msg, product, version, appliance, appliance_id, alert, )
supermod.alerts.subclass = alertsSub
# end class alertsSub


class alertSub(supermod.alert):
    def __init__(self, product=None, severity=None, name=None, version=None, sensor=None, id=None, appliance_id=None, explanation=None, src=None, alert_url=None, action=None, locations=None, occurred=None, dst=None, smtp_message=None, interface=None):
        super(alertSub, self).__init__(product, severity, name, version, sensor, id, appliance_id, explanation, src, alert_url, action, locations, occurred, dst, smtp_message, interface, )
supermod.alert.subclass = alertSub
# end class alertSub


class explanationSub(supermod.explanation):
    def __init__(self, protocol=None, urls=None, analysis=None, malware_detected=None, cnc_services=None, os_changes=None, static_analysis=None, service=None, anomaly=None, target_application=None, target_os=None, osinfo=None, stolen_data=None):
        super(explanationSub, self).__init__(protocol, urls, analysis, malware_detected, cnc_services, os_changes, static_analysis, service, anomaly, target_application, target_os, osinfo, stolen_data, )
supermod.explanation.subclass = explanationSub
# end class explanationSub


class malwareSub(supermod.malware):
    def __init__(self, name=None, parent=None, scan=None, origid=None, malicious=None, content=None, archives=None, sid=None, type_=None, stype=None, note=None, url=None, profile=None, md5sum=None, application=None, http_header=None, domain=None, user=None, original=None, downloaded_at=None, executed_at=None, objurl=None):
        super(malwareSub, self).__init__(name, parent, scan, origid, malicious, content, archives, sid, type_, stype, note, url, profile, md5sum, application, http_header, domain, user, original, downloaded_at, executed_at, objurl, )
supermod.malware.subclass = malwareSub
# end class malwareSub


class cnc_serviceSub(supermod.cnc_service):
    def __init__(self, protocol=None, port=None, address=None, channel=None, location=None):
        super(cnc_serviceSub, self).__init__(protocol, port, address, channel, location, )
supermod.cnc_service.subclass = cnc_serviceSub
# end class cnc_serviceSub


class stolen_dataSub(supermod.stolen_data):
    def __init__(self, event_id=None, size=None, info=None):
        super(stolen_dataSub, self).__init__(event_id, size, info, )
supermod.stolen_data.subclass = stolen_dataSub
# end class stolen_dataSub


class infoSub(supermod.info):
    def __init__(self, decrypted=None, type_=None, encryption=None, description=None, severity=None, field=None):
        super(infoSub, self).__init__(decrypted, type_, encryption, description, severity, field, )
supermod.info.subclass = infoSub
# end class infoSub


class fieldSub(supermod.field):
    def __init__(self, name=None, valueOf_=None):
        super(fieldSub, self).__init__(name, valueOf_, )
supermod.field.subclass = fieldSub
# end class fieldSub


class srcSub(supermod.src):
    def __init__(self, vlan=None, ip=None, mac=None, host=None, port=None, domain=None, smtp_mail_from=None, repository=None, url=None, proxy=None):
        super(srcSub, self).__init__(vlan, ip, mac, host, port, domain, smtp_mail_from, repository, url, proxy, )
supermod.src.subclass = srcSub
# end class srcSub


class staticSub(supermod.static):
    def __init__(self, tool=None, version=None, valueOf_=None):
        super(staticSub, self).__init__(tool, version, valueOf_, )
supermod.static.subclass = staticSub
# end class staticSub


class OSCChangeSetSub(supermod.OSCChangeSet):
    def __init__(self, analysis=None, os=None, os_monitor=None, event_logger=None, apicall=None, application=None, codeinjection=None, driver=None, exploitcode=None, file=None, folder=None, heapspraying=None, malicious_alert=None, mutex=None, network=None, process=None, process_packed=None, processstats=None, regkey=None, uac=None, keyloggerdetected=None, HardwareAccessDetection=None, dll_loaded=None, appexception=None, debugcontrol=None, hiddenproc=None, dll_exports=None, guestos_not_pingable=None, SSDT=None, spooler_dll_injection=None, detection_monitor_killed=None, started=None, firefox=None, AsyncKeyLogger=None, CmdLine=None, systemshutdown=None, os_inactivity_send_keys=None, end_of_report=None, extensiontype_=None):
        super(OSCChangeSetSub, self).__init__(analysis, os, os_monitor, event_logger, apicall, application, codeinjection, driver, exploitcode, file, folder, heapspraying, malicious_alert, mutex, network, process, process_packed, processstats, regkey, uac, keyloggerdetected, HardwareAccessDetection, dll_loaded, appexception, debugcontrol, hiddenproc, dll_exports, guestos_not_pingable, SSDT, spooler_dll_injection, detection_monitor_killed, started, firefox, AsyncKeyLogger, CmdLine, systemshutdown, os_inactivity_send_keys, end_of_report, extensiontype_, )
supermod.OSCChangeSet.subclass = OSCChangeSetSub
# end class OSCChangeSetSub


class applicationSub(supermod.application):
    def __init__(self, app_name=None, sequenceNumber=None):
        super(applicationSub, self).__init__(app_name, sequenceNumber, )
supermod.application.subclass = applicationSub
# end class applicationSub


class osSub(supermod.os):
    def __init__(self, sequenceNumber=None, sp=None, name=None, version=None):
        super(osSub, self).__init__(sequenceNumber, sp, name, version, )
supermod.os.subclass = osSub
# end class osSub


class event_loggerSub(supermod.event_logger):
    def __init__(self, date=None, build_=None, time=None):
        super(event_loggerSub, self).__init__(date, build_, time, )
supermod.event_logger.subclass = event_loggerSub
# end class event_loggerSub


class analysisSub(supermod.analysis):
    def __init__(self, sequenceNumber=None, product=None, ftype=None, mode=None, version=None):
        super(analysisSub, self).__init__(sequenceNumber, product, ftype, mode, version, )
supermod.analysis.subclass = analysisSub
# end class analysisSub


class keyloggerdetectedSub(supermod.keyloggerdetected):
    def __init__(self, sequenceNumber=None, processinfo=None, idhook=None, hookprocaddr=None, moduleaddr=None, threadid=None, module_name=None, md5sum=None, sha1sum=None, symbol_name=None, symbol_displacement=None):
        super(keyloggerdetectedSub, self).__init__(sequenceNumber, processinfo, idhook, hookprocaddr, moduleaddr, threadid, module_name, md5sum, sha1sum, symbol_name, symbol_displacement, )
supermod.keyloggerdetected.subclass = keyloggerdetectedSub
# end class keyloggerdetectedSub


class HardwareAccessDetectionSub(supermod.HardwareAccessDetection):
    def __init__(self, sequenceNumber=None, processinfo=None, function=None, device=None, handle=None, size=None, address=None):
        super(HardwareAccessDetectionSub, self).__init__(sequenceNumber, processinfo, function, device, handle, size, address, )
supermod.HardwareAccessDetection.subclass = HardwareAccessDetectionSub
# end class HardwareAccessDetectionSub


class dll_loadedSub(supermod.dll_loaded):
    def __init__(self, sequenceNumber=None, processinfo=None, dllpath=None, md5sum=None, sha1sum=None):
        super(dll_loadedSub, self).__init__(sequenceNumber, processinfo, dllpath, md5sum, sha1sum, )
supermod.dll_loaded.subclass = dll_loadedSub
# end class dll_loadedSub


class apicallSub(supermod.apicall):
    def __init__(self, repeat=None, sequenceNumber=None, processinfo=None, dllname=None, apiname=None, address=None, params=None):
        super(apicallSub, self).__init__(repeat, sequenceNumber, processinfo, dllname, apiname, address, params, )
supermod.apicall.subclass = apicallSub
# end class apicallSub


class codeinjectionSub(supermod.codeinjection):
    def __init__(self, mode=None, sequenceNumber=None, source=None, target=None):
        super(codeinjectionSub, self).__init__(mode, sequenceNumber, source, target, )
supermod.codeinjection.subclass = codeinjectionSub
# end class codeinjectionSub


class sourceSub(supermod.source):
    def __init__(self, sequenceNumber=None, processinfo=None):
        super(sourceSub, self).__init__(sequenceNumber, processinfo, )
supermod.source.subclass = sourceSub
# end class sourceSub


class targetSub(supermod.target):
    def __init__(self, sequenceNumber=None, processinfo=None):
        super(targetSub, self).__init__(sequenceNumber, processinfo, )
supermod.target.subclass = targetSub
# end class targetSub


class driverSub(supermod.driver):
    def __init__(self, mode=None, sequenceNumber=None, processinfo=None, registrypath=None, driverimage=None, method=None):
        super(driverSub, self).__init__(mode, sequenceNumber, processinfo, registrypath, driverimage, method, )
supermod.driver.subclass = driverSub
# end class driverSub


class exploitcodeSub(supermod.exploitcode):
    def __init__(self, sequenceNumber=None, processinfo=None, dllname=None, apiname=None, address=None, params=None, callstack=None):
        super(exploitcodeSub, self).__init__(sequenceNumber, processinfo, dllname, apiname, address, params, callstack, )
supermod.exploitcode.subclass = exploitcodeSub
# end class exploitcodeSub


class fileSub(supermod.file):
    def __init__(self, type_=None, mode=None, sequenceNumber=None, value=None, filesize=None, md5sum=None, sha1sum=None, target=None, processinfo=None, old_name=None, new_name=None, creationTime=None, lastWriteTime=None, changeTime=None, newCreationTime=None, newLastWriteTime=None, newChangeTime=None, fid=None):
        super(fileSub, self).__init__(type_, mode, sequenceNumber, value, filesize, md5sum, sha1sum, target, processinfo, old_name, new_name, creationTime, lastWriteTime, changeTime, newCreationTime, newLastWriteTime, newChangeTime, fid, )
supermod.file.subclass = fileSub
# end class fileSub


class folderSub(supermod.folder):
    def __init__(self, mode=None, sequenceNumber=None, value=None, old_name=None, new_name=None, creationTime=None, lastWriteTime=None, changeTime=None, newCreationTime=None, newLastWriteTime=None, newChangeTime=None, processinfo=None):
        super(folderSub, self).__init__(mode, sequenceNumber, value, old_name, new_name, creationTime, lastWriteTime, changeTime, newCreationTime, newLastWriteTime, newChangeTime, processinfo, )
supermod.folder.subclass = folderSub
# end class folderSub


class heapsprayingSub(supermod.heapspraying):
    def __init__(self, type_=None, name=None, sequenceNumber=None, processinfo=None, pattern=None, blocksize=None, address=None, bytesreceived=None, totalmemory=None, lastbytesreceived=None, lasttotalmemory=None, incrementCount=None):
        super(heapsprayingSub, self).__init__(type_, name, sequenceNumber, processinfo, pattern, blocksize, address, bytesreceived, totalmemory, lastbytesreceived, lasttotalmemory, incrementCount, )
supermod.heapspraying.subclass = heapsprayingSub
# end class heapsprayingSub


class malicious_alertSub(supermod.malicious_alert):
    def __init__(self, classtype=None, sequenceNumber=None, msg=None, display_msg=None):
        super(malicious_alertSub, self).__init__(classtype, sequenceNumber, msg, display_msg, )
supermod.malicious_alert.subclass = malicious_alertSub
# end class malicious_alertSub


class mutexSub(supermod.mutex):
    def __init__(self, sequenceNumber=None, value=None, processinfo=None):
        super(mutexSub, self).__init__(sequenceNumber, value, processinfo, )
supermod.mutex.subclass = mutexSub
# end class mutexSub


class networkSub(supermod.network):
    def __init__(self, mode=None, sequenceNumber=None, processinfo=None, protocol_type=None, destination_port=None, listen_port=None, ipaddress=None, http_request=None, qtype=None, hostname=None, winsock_res=None, dns_response_code=None):
        super(networkSub, self).__init__(mode, sequenceNumber, processinfo, protocol_type, destination_port, listen_port, ipaddress, http_request, qtype, hostname, winsock_res, dns_response_code, )
supermod.network.subclass = networkSub
# end class networkSub


class processSub(supermod.process):
    def __init__(self, mode=None, sequenceNumber=None, value=None, pid=None, ppid=None, parentname=None, cmdline=None, filesize=None, md5sum=None, sha1sum=None, packed=None, gui=None, fid=None):
        super(processSub, self).__init__(mode, sequenceNumber, value, pid, ppid, parentname, cmdline, filesize, md5sum, sha1sum, packed, gui, fid, )
supermod.process.subclass = processSub
# end class processSub


class process_packedSub(supermod.process_packed):
    def __init__(self, sequenceNumber=None, processinfo=None):
        super(process_packedSub, self).__init__(sequenceNumber, processinfo, )
supermod.process_packed.subclass = process_packedSub
# end class process_packedSub


class processstatsSub(supermod.processstats):
    def __init__(self, sequenceNumber=None, processinfo=None, bytesreceived=None, totalmemory=None, id=None, deltatime=None):
        super(processstatsSub, self).__init__(sequenceNumber, processinfo, bytesreceived, totalmemory, id, deltatime, )
supermod.processstats.subclass = processstatsSub
# end class processstatsSub


class regkeySub(supermod.regkey):
    def __init__(self, mode=None, sequenceNumber=None, value=None, processinfo=None):
        super(regkeySub, self).__init__(mode, sequenceNumber, value, processinfo, )
supermod.regkey.subclass = regkeySub
# end class regkeySub


class os_inactivity_send_keysSub(supermod.os_inactivity_send_keys):
    def __init__(self, sequenceNumber=None):
        super(os_inactivity_send_keysSub, self).__init__(sequenceNumber, )
supermod.os_inactivity_send_keys.subclass = os_inactivity_send_keysSub
# end class os_inactivity_send_keysSub


class end_of_reportSub(supermod.end_of_report):
    def __init__(self, sequenceNumber=None):
        super(end_of_reportSub, self).__init__(sequenceNumber, )
supermod.end_of_report.subclass = end_of_reportSub
# end class end_of_reportSub


class processinfoSub(supermod.processinfo):
    def __init__(self, sequenceNumber=None, pid=None, imagepath=None, md5sum=None):
        super(processinfoSub, self).__init__(sequenceNumber, pid, imagepath, md5sum, )
supermod.processinfo.subclass = processinfoSub
# end class processinfoSub


class paramsSub(supermod.params):
    def __init__(self, sequenceNumber=None, param=None):
        super(paramsSub, self).__init__(sequenceNumber, param, )
supermod.params.subclass = paramsSub
# end class paramsSub


class paramSub(supermod.param):
    def __init__(self, id=None, sequenceNumber=None, valueOf_=None):
        super(paramSub, self).__init__(id, sequenceNumber, valueOf_, )
supermod.param.subclass = paramSub
# end class paramSub


class callstackSub(supermod.callstack):
    def __init__(self, sequenceNumber=None, callstack_entry=None):
        super(callstackSub, self).__init__(sequenceNumber, callstack_entry, )
supermod.callstack.subclass = callstackSub
# end class callstackSub


class callstack_entrySub(supermod.callstack_entry):
    def __init__(self, sequenceNumber=None, frame_number=None, instruction_address=None, module_name=None, symbol_name=None, symbol_displacement=None):
        super(callstack_entrySub, self).__init__(sequenceNumber, frame_number, instruction_address, module_name, symbol_name, symbol_displacement, )
supermod.callstack_entry.subclass = callstack_entrySub
# end class callstack_entrySub


class fidSub(supermod.fid):
    def __init__(self, ads=None, sequenceNumber=None, valueOf_=None):
        super(fidSub, self).__init__(ads, sequenceNumber, valueOf_, )
supermod.fid.subclass = fidSub
# end class fidSub


class appexceptionSub(supermod.appexception):
    def __init__(self, sequenceNumber=None, processinfo=None, exception_faulting_address=None, exception_code=None, exception_level=None, exception_type=None, instruction_address=None, description=None, classification=None, bug_title=None):
        super(appexceptionSub, self).__init__(sequenceNumber, processinfo, exception_faulting_address, exception_code, exception_level, exception_type, instruction_address, description, classification, bug_title, )
supermod.appexception.subclass = appexceptionSub
# end class appexceptionSub


class debugcontrolSub(supermod.debugcontrol):
    def __init__(self, sequenceNumber=None, processinfo=None, controlcode=None, codedescription=None):
        super(debugcontrolSub, self).__init__(sequenceNumber, processinfo, controlcode, codedescription, )
supermod.debugcontrol.subclass = debugcontrolSub
# end class debugcontrolSub


class hiddenprocSub(supermod.hiddenproc):
    def __init__(self, mode=None, sequenceNumber=None, processinfo=None, imagename=None):
        super(hiddenprocSub, self).__init__(mode, sequenceNumber, processinfo, imagename, )
supermod.hiddenproc.subclass = hiddenprocSub
# end class hiddenprocSub


class dll_exportsSub(supermod.dll_exports):
    def __init__(self, sequenceNumber=None, dllname=None, exports=None):
        super(dll_exportsSub, self).__init__(sequenceNumber, dllname, exports, )
supermod.dll_exports.subclass = dll_exportsSub
# end class dll_exportsSub


class exportsSub(supermod.exports):
    def __init__(self, sequenceNumber=None, export_function=None):
        super(exportsSub, self).__init__(sequenceNumber, export_function, )
supermod.exports.subclass = exportsSub
# end class exportsSub


class AsyncKeyLoggerSub(supermod.AsyncKeyLogger):
    def __init__(self, name=None, sequenceNumber=None, processinfo=None, ProbePattern=None, Yields=None, Probes=None):
        super(AsyncKeyLoggerSub, self).__init__(name, sequenceNumber, processinfo, ProbePattern, Yields, Probes, )
supermod.AsyncKeyLogger.subclass = AsyncKeyLoggerSub
# end class AsyncKeyLoggerSub


class CmdLineSub(supermod.CmdLine):
    def __init__(self, sequenceNumber=None, value=None, ExitCode=None):
        super(CmdLineSub, self).__init__(sequenceNumber, value, ExitCode, )
supermod.CmdLine.subclass = CmdLineSub
# end class CmdLineSub


class spooler_dll_injectionSub(supermod.spooler_dll_injection):
    def __init__(self, sequenceNumber=None, processinfo=None, dllname=None, apiname=None, address=None, params=None):
        super(spooler_dll_injectionSub, self).__init__(sequenceNumber, processinfo, dllname, apiname, address, params, )
supermod.spooler_dll_injection.subclass = spooler_dll_injectionSub
# end class spooler_dll_injectionSub


class firefoxSub(supermod.firefox):
    def __init__(self, mode=None, sequenceNumber=None, old_homepage=None, new_homepage=None, pid=None):
        super(firefoxSub, self).__init__(mode, sequenceNumber, old_homepage, new_homepage, pid, )
supermod.firefox.subclass = firefoxSub
# end class firefoxSub


class systemshutdownSub(supermod.systemshutdown):
    def __init__(self, sequenceNumber=None, processinfo=None, action=None, actiondescription=None):
        super(systemshutdownSub, self).__init__(sequenceNumber, processinfo, action, actiondescription, )
supermod.systemshutdown.subclass = systemshutdownSub
# end class systemshutdownSub


class uacSub(supermod.uac):
    def __init__(self, mode=None, value=None, status=None, accountenabled=None, accountcreated=None, accountname=None, passwordchange=None, group=None, memberadded=None, memberremoved=None, valueOf_=None, mixedclass_=None, content_=None):
        super(uacSub, self).__init__(mode, value, status, accountenabled, accountcreated, accountname, passwordchange, group, memberadded, memberremoved, valueOf_, mixedclass_, content_, )
supermod.uac.subclass = uacSub
# end class uacSub


class os_monitorSub(supermod.os_monitor):
    def __init__(self, date=None, build_=None, sequenceNumber=None, time=None):
        super(os_monitorSub, self).__init__(date, build_, sequenceNumber, time, )
supermod.os_monitor.subclass = os_monitorSub
# end class os_monitorSub


class dstTypeSub(supermod.dstType):
    def __init__(self, mac=None, port=None, ip=None, smtp_to=None, smtp_cc=None):
        super(dstTypeSub, self).__init__(mac, port, ip, smtp_to, smtp_cc, )
supermod.dstType.subclass = dstTypeSub
# end class dstTypeSub


class smtp_messageTypeSub(supermod.smtp_messageType):
    def __init__(self, id=None, subject=None, smtp_header=None, last_malware=None, protocol=None, date=None):
        super(smtp_messageTypeSub, self).__init__(id, subject, smtp_header, last_malware, protocol, date, )
supermod.smtp_messageType.subclass = smtp_messageTypeSub
# end class smtp_messageTypeSub


class interfaceTypeSub(supermod.interfaceType):
    def __init__(self, mode=None, label=None, valueOf_=None):
        super(interfaceTypeSub, self).__init__(mode, label, valueOf_, )
supermod.interfaceType.subclass = interfaceTypeSub
# end class interfaceTypeSub


class malware_detectedTypeSub(supermod.malware_detectedType):
    def __init__(self, malware=None):
        super(malware_detectedTypeSub, self).__init__(malware, )
supermod.malware_detectedType.subclass = malware_detectedTypeSub
# end class malware_detectedTypeSub


class cnc_servicesTypeSub(supermod.cnc_servicesType):
    def __init__(self, cnc_service=None):
        super(cnc_servicesTypeSub, self).__init__(cnc_service, )
supermod.cnc_servicesType.subclass = cnc_servicesTypeSub
# end class cnc_servicesTypeSub


class os_changesTypeSub(supermod.os_changesType):
    def __init__(self, analysis=None, os=None, os_monitor=None, event_logger=None, apicall=None, application=None, codeinjection=None, driver=None, exploitcode=None, file=None, folder=None, heapspraying=None, malicious_alert=None, mutex=None, network=None, process=None, process_packed=None, processstats=None, regkey=None, uac=None, keyloggerdetected=None, HardwareAccessDetection=None, dll_loaded=None, appexception=None, debugcontrol=None, hiddenproc=None, dll_exports=None, guestos_not_pingable=None, SSDT=None, spooler_dll_injection=None, detection_monitor_killed=None, started=None, firefox=None, AsyncKeyLogger=None, CmdLine=None, systemshutdown=None, os_inactivity_send_keys=None, end_of_report=None, osinfo=None, version=None, id=None):
        super(os_changesTypeSub, self).__init__(analysis, os, os_monitor, event_logger, apicall, application, codeinjection, driver, exploitcode, file, folder, heapspraying, malicious_alert, mutex, network, process, process_packed, processstats, regkey, uac, keyloggerdetected, HardwareAccessDetection, dll_loaded, appexception, debugcontrol, hiddenproc, dll_exports, guestos_not_pingable, SSDT, spooler_dll_injection, detection_monitor_killed, started, firefox, AsyncKeyLogger, CmdLine, systemshutdown, os_inactivity_send_keys, end_of_report, osinfo, version, id, )
supermod.os_changesType.subclass = os_changesTypeSub
# end class os_changesTypeSub


class static_analysisTypeSub(supermod.static_analysisType):
    def __init__(self, static=None):
        super(static_analysisTypeSub, self).__init__(static, )
supermod.static_analysisType.subclass = static_analysisTypeSub
# end class static_analysisTypeSub


def get_root_tag(node):
    tag = supermod.Tag_pattern_.match(node.tag).groups()[-1]
    rootClass = None
    rootClass = supermod.GDSClassesMapping.get(tag)
    if rootClass is None and hasattr(supermod, tag):
        rootClass = getattr(supermod, tag)
    return tag, rootClass


def parse(inFilename, silence=False):
    parser = None
    doc = parsexml_(inFilename, parser)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    if rootClass is None:
        rootTag = 'alerts'
        rootClass = supermod.alerts
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    if not silence:
        sys.stdout.write('<?xml version="1.0" ?>\n')
        rootObj.export(
            sys.stdout, 0, name_=rootTag,
            namespacedef_='',
            pretty_print=True)
    return rootObj


def parseEtree(inFilename, silence=False):
    parser = None
    doc = parsexml_(inFilename, parser)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    if rootClass is None:
        rootTag = 'alerts'
        rootClass = supermod.alerts
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    mapping = {}
    rootElement = rootObj.to_etree(None, name_=rootTag, mapping_=mapping)
    reverse_mapping = rootObj.gds_reverse_node_mapping(mapping)
    if not silence:
        content = etree_.tostring(
            rootElement, pretty_print=True,
            xml_declaration=True, encoding="utf-8")
        sys.stdout.write(content)
        sys.stdout.write('\n')
    return rootObj, rootElement, mapping, reverse_mapping


def parseString(inString, silence=False):
    from StringIO import StringIO
    parser = None
    doc = parsexml_(StringIO(inString), parser)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    if rootClass is None:
        rootTag = 'alerts'
        rootClass = supermod.alerts
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    if not silence:
        sys.stdout.write('<?xml version="1.0" ?>\n')
        rootObj.export(
            sys.stdout, 0, name_=rootTag,
            namespacedef_='')
    return rootObj


def parseLiteral(inFilename, silence=False):
    parser = None
    doc = parsexml_(inFilename, parser)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    if rootClass is None:
        rootTag = 'alerts'
        rootClass = supermod.alerts
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    if not silence:
        sys.stdout.write('#from fealerts import *\n\n')
        sys.stdout.write('import fealerts as model_\n\n')
        sys.stdout.write('rootObj = model_.rootClass(\n')
        rootObj.exportLiteral(sys.stdout, 0, name_=rootTag)
        sys.stdout.write(')\n')
    return rootObj


USAGE_TEXT = """
Usage: python ???.py <infilename>
"""


def usage():
    print(USAGE_TEXT)
    sys.exit(1)


def main():
    args = sys.argv[1:]
    if len(args) != 1:
        usage()
    infilename = args[0]
    parse(infilename)


if __name__ == '__main__':
    #import pdb; pdb.set_trace()
    main()
