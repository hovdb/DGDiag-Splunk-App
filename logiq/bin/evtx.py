#!/usr/bin/env python

import sys

# access built-in module such as mmap
sys.path.append('/usr/lib/python3.7/lib-dynload')
# append the Splunk's packages lib.  This is where Evtx is expected to be installed
sys.path.append('/usr/lib/python3.7/site-packages')

import Evtx.Evtx as evtx
import Evtx.Views as e_views

from xml.dom import minidom

from builtins import str, int
import logging

SCHEME = """<scheme>
    <title>Microsoft Windows Event File</title>
    <description>Get data from EVTX file</description>
    <streaming_mode>xml</streaming_mode>

    <endpoint>
        <args>
            <arg name="host_segment">
                <title>Segment number in path</title>
                <description>Specify which segment of the source path to set as the Host field.
                    For example: 3 (sets to 'hostname' for the path /var/log/hostname/)
                </description>
                <data_type>number</data_type>
                <required_on_create>false</required_on_create>
                <required_on_edit>false</required_on_edit>
            </arg>
        </args>
    </endpoint>
</scheme>
"""

def get_files(stanza):
    from urllib.parse import urlparse
    from pathlib import PurePath, Path

    uo = urlparse(stanza, 'file', allow_fragments=False)
    pp = PurePath(uo.path)
    p = Path(pp.root)
    # remove the root
    parts = pp.parts[1:] if pp.root else pp.parts
    # Convert ... to **
    parts = ['**' if part=='...' else part for part in parts]
    # Find all matching files
    files = list(p.glob(str(PurePath().joinpath(*parts))))
    return files
    
def validate_conf(config, key):
    if key not in config:
        raise Exception("Invalid configuration received from Splunk: key '%s' is missing." % key)

def get_config():
    config = {}

    try:
        # read everything from stdin
        config_str = sys.stdin.read()

        # parse the config XML
        doc = minidom.parseString(config_str)
        root = doc.documentElement
        conf_node = root.getElementsByTagName("configuration")[0]
        if conf_node:
            logging.debug("XML: found configuration")
            stanza = conf_node.getElementsByTagName("stanza")[0]
            if stanza:
                stanza_name = stanza.getAttribute("name")
                if stanza_name:
                    logging.debug("XML: found stanza " + stanza_name)
                    config["name"] = stanza_name

                    params = stanza.getElementsByTagName("param")
                    for param in params:
                        param_name = param.getAttribute("name")
                        logging.debug("XML: found param '%s'" % param_name)
                        if param_name and param.firstChild and \
                           param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                            data = param.firstChild.data
                            config[param_name] = data
                            logging.debug("XML: '%s' -> '%s'" % (param_name, data))

        checkpnt_node = root.getElementsByTagName("checkpoint_dir")[0]
        if checkpnt_node and checkpnt_node.firstChild and \
           checkpnt_node.firstChild.nodeType == checkpnt_node.firstChild.TEXT_NODE:
            config["checkpoint_dir"] = checkpnt_node.firstChild.data

        if not config:
            raise Exception("Invalid configuration received from Splunk.")

        # just some validation: make sure these keys are present (required)
        validate_conf(config, "name")
        validate_conf(config, "checkpoint_dir")
    except Exception as e:
        raise Exception("Error getting Splunk configuration via STDIN: %s" % str(e))

    return config

def show_scheme():
    print(SCHEME)

def parsed_date(dstr):
    from datetime import datetime
    
    ts = None
    try:
        ts = datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        ts = datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S')
    return ts

def show_events(config):
    from xml.sax import saxutils

    print("<stream>")
    config_stanza = config['name']
    event_start_tag = "<event stanza={} unbroken={}>".format(saxutils.quoteattr(config_stanza), saxutils.quoteattr('1'))
    files = get_files(config_stanza)
    host_segment = config.get('host_segment')
    for file in files:
        # reset host for a new file
        host = config.get('host')
        # if we have a host_segment, obtain the segment of the file
        if host_segment is not None:
            host_segment = int(host_segment)
            for i, part in enumerate(file.parts):
                if i == host_segment:
                    host = part
                    break

        host_tag = ""
        if host is not None:
            host_tag = "<host>{}</host>".format(saxutils.escape(host))
        str_file = str(file)
        source_tag = "<source>{}</source>".format(saxutils.escape(str_file))

        with evtx.Evtx(str_file) as log:

            for record in log.records():
                xml = record.xml()
                doc = minidom.parseString(xml)
                root = doc.documentElement
                system_time = None
                time_created = root.getElementsByTagName("TimeCreated")[0]
                if time_created:
                    system_time = parsed_date(time_created.getAttribute("SystemTime"))
                    
                print(event_start_tag)
                if system_time is not None:
                    print("<time>%0.6lf</time>" % system_time.timestamp())
                print(host_tag)
                print(source_tag)
                print("<data>%s</data>" % saxutils.escape(xml))
                print("<done/>")
                print("</event>")

    print("</stream>")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            show_scheme()
        
    else:
        config=get_config()

        show_events(config)

    sys.exit(0)
