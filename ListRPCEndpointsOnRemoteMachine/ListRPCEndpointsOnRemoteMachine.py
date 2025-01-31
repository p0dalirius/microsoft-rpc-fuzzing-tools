#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ListRPCEndpointsOnRemoteMachine.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 Jan 2023

import argparse
import json
import datetime
import time
import os
import sys
from impacket.http import AUTH_NTLM
from impacket import uuid, version
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpch import RPC_PROXY_INVALID_RPC_PORT_ERR, RPC_PROXY_CONN_A1_0X6BA_ERR, RPC_PROXY_CONN_A1_404_ERR, RPC_PROXY_RPC_OUT_DATA_404_ERR


def list_rpc_endpoints(options, lmhash, nthash, debug=False):
    KNOWN_PROTOCOLS = {
        '135': {
            'bindstr': r'ncacn_ip_tcp:%s[135]'
        },
        '139': {
            'bindstr': r'ncacn_np:%s[\pipe\epmapper]'
        },
        '443': {
            'bindstr': r'ncacn_http:[593,RpcProxy=%s:443]'
        },
        '445': {
            'bindstr': r'ncacn_np:%s[\pipe\epmapper]'
        },
        '593': {
            'bindstr': r'ncacn_http:%s'
        }
    }
    if debug:
        print('[debug] Retrieving endpoint list from %s' % options.target)

    entries = []

    options.stringbinding = KNOWN_PROTOCOLS[options.port]['bindstr'] % options.target
    if debug:
        print('[debug] StringBinding %s' % options.stringbinding)
    rpctransport = transport.DCERPCTransportFactory(options.stringbinding)

    if options.port in [139, 445]:
        # Setting credentials for SMB
        rpctransport.set_credentials(options.username, options.password, options.domain, lmhash, nthash)

        # Setting remote host and port for SMB
        rpctransport.setRemoteHost(options.target_ip)
        rpctransport.set_dport(options.port)
    elif options.port in [443]:
        # Setting credentials only for RPC Proxy, but not for the MSRPC level
        rpctransport.set_credentials(options.username, options.password, options.domain, lmhash, nthash)

        # Usually when a server doesn't support NTLM, it also doesn't expose epmapper (nowadays
        # only RDG servers may potentially expose a epmapper via RPC Proxy).
        #
        # Also if the auth is not NTLM, there is no way to get a target
        # NetBIOS name, but epmapper ACL requires you to specify it.
        rpctransport.set_auth_type(AUTH_NTLM)
    else:
        # We don't need to authenticate to 135 and 593 ports
        pass

    try:
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
        #dce.bind(epm.MSRPC_UUID_PORTMAP)
        #rpcepm = epm.DCERPCEpm(dce)
        entries = epm.hept_lookup(None, dce=dce)
        dce.disconnect()
    except Exception as error_text:
        # raise
        # This may contain UTF-8
        if debug:
            print("[error] Protocol failed: %s" % error_text)

        if (RPC_PROXY_INVALID_RPC_PORT_ERR in error_text) \
                or (RPC_PROXY_RPC_OUT_DATA_404_ERR in error_text) \
                or (RPC_PROXY_CONN_A1_404_ERR in error_text) \
                or (RPC_PROXY_CONN_A1_0X6BA_ERR in error_text):
            if debug:
                print("[error] This usually means the target does not allow to connect to its epmapper using RpcProxy.")
            return

    # Display results.

    endpoints = {}
    # Let's groups the UUIDS
    for entry in entries:
        binding = epm.PrintStringBinding(entry['tower']['Floors'])
        _uuid = uuid.bin_to_string(entry['tower']['Floors'][0].fields["InterfaceUUID"])
        _version = "%d.%d" % (entry['tower']['Floors'][0].fields["MajorVersion"], entry['tower']['Floors'][0].fields["MinorVersion"])
        tmpUUID = str(entry['tower']['Floors'][0])
        if _uuid not in endpoints.keys():
            endpoints[_uuid] = {}
        if _version not in endpoints[_uuid].keys():
            endpoints[_uuid][_version] = {}
            endpoints[_uuid][_version]['bindings'] = list()

        if uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18] in epm.KNOWN_UUIDS:
            endpoints[_uuid][_version]['exe'] = epm.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]
        else:
            endpoints[_uuid][_version]['exe'] = None
            # print(uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18],': "", #', _uuid)

        endpoints[_uuid][_version]['annotation'] = entry['annotation'][:-1].decode('utf-8')

        endpoints[_uuid][_version]['bindings'].append(binding)

        if _uuid in epm.KNOWN_PROTOCOLS:
            endpoints[_uuid][_version]['protocol'] = epm.KNOWN_PROTOCOLS[_uuid]
        else:
            endpoints[_uuid][_version]['protocol'] = None

    return endpoints


def print_results(results):
    for uuid in sorted(results.keys()):
        for version in sorted(results[uuid].keys()):
            for binding in sorted(results[uuid][version]["bindings"]):
                message = " - %s v%s: %s" % (uuid, version, binding)
                if results[uuid][version]["exe"] is not None:
                    message += " (%s)" % results[uuid][version]["exe"]
                if results[uuid][version]["protocol"] is not None:
                    message += " %s" % results[uuid][version]["protocol"]
                if results[uuid][version]["annotation"] is not None and len(results[uuid][version]["annotation"]) != 0:
                    message += ", %s" % results[uuid][version]["annotation"]
                print(message)


def print_results_live(results_before, results_now):
    timenow = datetime.datetime.now().strftime("%Y-%m-%d %Hh:%Mm:%Ss")

    for uuid in sorted(list(results_before.keys()) + list(results_now.keys())):
        all_versions = []
        if uuid in results_before.keys():
            all_versions += results_before[uuid].keys()
        if uuid in results_now.keys():
            all_versions += results_now[uuid].keys()

        for version in all_versions:
            all_bindings = []
            if uuid in results_before.keys():
                if version in results_before[uuid].keys():
                    all_bindings += results_before[uuid][version]["bindings"]
            if uuid in results_now.keys():
                if version in results_now[uuid].keys():
                    all_bindings += results_now[uuid][version]["bindings"]

            for binding in sorted(all_bindings):
                existing_before = False
                if uuid in results_before.keys():
                    if version in results_before[uuid].keys():
                        if binding in results_before[uuid][version]["bindings"]:
                            existing_before = True
                existing_now = False
                if uuid in results_now.keys():
                    if version in results_now[uuid].keys():
                        if binding in results_now[uuid][version]["bindings"]:
                            existing_now = True

                if existing_before == True and existing_now == False:
                    message = "%s v%s: %s" % (uuid, version, binding)
                    if results_before[uuid][version]["exe"] is not None:
                        message += " (%s)" % results_before[uuid][version]["exe"]
                    if results_before[uuid][version]["protocol"] is not None:
                        message += " %s" % results_before[uuid][version]["protocol"]
                    if results_before[uuid][version]["annotation"] is not None and len(results_before[uuid][version]["annotation"]) != 0:
                        message += ", %s" % results_before[uuid][version]["annotation"]

                    print("[\x1b[93m%s\x1b[0m] Endpoint was \x1b[1;91mdeleted\x1b[0m: %s" % (timenow, message))

                if existing_before == False and existing_now == True:
                    message = "%s v%s: %s" % (uuid, version, binding)
                    if results_now[uuid][version]["exe"] is not None:
                        message += " (%s)" % results_now[uuid][version]["exe"]
                    if results_now[uuid][version]["protocol"] is not None:
                        message += " %s" % results_now[uuid][version]["protocol"]
                    if results_now[uuid][version]["annotation"] is not None and len(results_now[uuid][version]["annotation"]) != 0:
                        message += ", %s" % results_now[uuid][version]["annotation"]

                    print("[\x1b[93m%s\x1b[0m] Endpoint was \x1b[1;92mcreated\x1b[0m: %s" % (timenow, message))


def parseArgs():
    print("ListRPCEndpointsOnRemoteMachine v1.2 - by Remi GASCOU (Podalirius)\n")

    parser = argparse.ArgumentParser(add_help=True, description="A script to list available SMB pipes remotely on a Windows machine through the IPC$ share.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode. (default: False)")

    group_creds = parser.add_argument_group('Credentials')
    group_creds.add_argument("-u", "--username", default="", help="Username to authenticate to the endpoint.")
    group_creds.add_argument("-p", "--password", default="", help="Password to authenticate to the endpoint. (if omitted, it will be asked unless -no-pass is specified)")
    group_creds.add_argument("-d", "--domain", default="", help="Windows domain name to authenticate to the endpoint.")
    group_creds.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    group_creds.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    group_creds.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")

    group = parser.add_argument_group('Connection')
    group.add_argument("--target", required=True, action="store", metavar="ip address", help="Target machine.")
    group.add_argument('--target-ip', action='store', metavar="ip address", help='IP Address of the target machine. If ommited it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('--port', choices=['135', '139', '443', '445', '593'], nargs='?', default='135', metavar="destination port", help='Destination port to connect to RPC Endpoint Mapper')

    parser.add_argument("-J", "--json", default=None, type=str, help="Write results to a json file instead of printing them. (default: False)")
    parser.add_argument("-L", "--live", action="store_true", help="Live mode, lists created and deleted pipes every second. (default: False)")

    options = parser.parse_args()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash, nthash = '', ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass

        options.password = getpass("Password:")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return options, lmhash, nthash


if __name__ == '__main__':
    options, lmhash, nthash = parseArgs()

    if options.live:
        try:
            print("[>] Listing created and deleted RPC endpoints from epmapper every second ... ")
            results_now = list_rpc_endpoints(options, lmhash, nthash, debug=options.verbose)
            results_before = results_now.copy()
            while True:
                time.sleep(1)
                results_now = list_rpc_endpoints(options, lmhash, nthash, debug=options.verbose)
                print_results_live(results_before, results_now)
                results_before = results_now.copy()

        except KeyboardInterrupt as e:
            pass
    else:
        print("[>] Listing RPC endpoints from epmapper ... ")
        endpoints = list_rpc_endpoints(options, lmhash, nthash, debug=options.verbose)
        if options.json is not None:
            basepath = os.path.dirname(options.json)
            filename = os.path.basename(options.json)
            if basepath not in [".", ""]:
                if not os.path.exists(basepath):
                    os.makedirs(basepath)
                path_to_file = basepath + os.path.sep + filename
            else:
                path_to_file = filename
            f = open(path_to_file, 'w')
            f.write(json.dumps(endpoints, indent=4))
            f.close()
        else:
            print_results(endpoints)
        print("[+] Found %d RPC endpoints." % len(endpoints))

