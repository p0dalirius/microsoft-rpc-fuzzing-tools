#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ListAvailablePipesOnRemoteMachine.py
# Author             : Podalirius (@podalirius_)
# Date created       : 9 Jul 2022


import argparse
import datetime
import sys
import time
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError
from impacket.dcerpc.v5 import transport
import sys


def can_connect_to_pipe(target, pipe, targetIp=None, verbose=False):
    ncan_target = r'ncacn_np:%s[%s]' % (target, pipe)
    __rpctransport = transport.DCERPCTransportFactory(ncan_target)

    if hasattr(__rpctransport, 'set_credentials'):
        __rpctransport.set_credentials(username="", password="", domain="", lmhash="", nthash="")

    if targetIp is not None:
        __rpctransport.setRemoteHost(targetIp)

    dce = __rpctransport.get_dce_rpc()
    # dce.set_auth_type(RPC_C_AUTHN_WINNT)
    # dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

    if verbose:
        print("   [>] Connecting to %s ... " % ncan_target, end="")
    sys.stdout.flush()
    try:
        dce.connect()
    except Exception as e:
        if verbose:
            print("\x1b[1;91mfail\x1b[0m")
            print("   [!] Something went wrong, check error status => %s" % str(e))
        return None
    else:
        if verbose:
            print("\x1b[1;92msuccess\x1b[0m")
        return dce



def list_remote_pipes(options, lmhash, nthash, share='IPC$', maxdepth=-1, debug=False):
    pipes = []
    try:
        smbClient = SMBConnection(options.target, options.target_ip, sess_port=int(options.port))
        dialect = smbClient.getDialect()
        if options.kerberos is True:
            smbClient.kerberosLogin(options.username, options.password, options.domain, lmhash, nthash, options.aesKey, options.dc_ip)
        else:
            smbClient.login(options.username, options.password, options.domain, lmhash, nthash)
        if smbClient.isGuestSession() > 0:
            if options.verbose:
                print("[>] GUEST Session Granted")
        else:
            if options.verbose:
                print("[>] USER Session Granted")
    except Exception as e:
        if debug:
            print(e)
        return pipes

    # Breadth-first search algorithm to recursively find .extension files
    searchdirs = [""]
    depth = 0
    while len(searchdirs) != 0 and ((depth <= maxdepth) or (maxdepth == -1)):
        depth += 1
        next_dirs = []
        for sdir in searchdirs:
            if debug:
                print("[>] Searching in %s " % sdir)
            try:
                for sharedfile in smbClient.listPath(share, sdir + "*", password=None):
                    if sharedfile.get_longname() not in [".", ".."]:
                        if sharedfile.is_directory():
                            if debug:
                                print("[>] Found directory %s/" % sharedfile.get_longname())
                            next_dirs.append(sdir + sharedfile.get_longname() + "/")
                        else:
                            if debug:
                                print("[>] Found file %s" % sharedfile.get_longname())
                            full_path = sdir + sharedfile.get_longname()
                            pipes.append(full_path)
            except SessionError as e:
                if debug:
                    print("[error] %s " % e)
        searchdirs = next_dirs
        if debug:
            print("[>] Next iteration with %d folders." % len(next_dirs))
    pipes = sorted(list(set(["\\PIPE\\" + f for f in pipes])), key=lambda x:x.lower())
    return pipes


def bruteforce_remote_pipes(options, debug=False):
    known_pipes = [
        r'\PIPE\atsvc',
        r'\PIPE\efsrpc',
        r'\PIPE\epmapper',
        r'\PIPE\eventlog',
        r'\PIPE\InitShutdown',
        r'\PIPE\lsass',
        r'\PIPE\lsarpc',
        r'\PIPE\LSM_API_service',
        r'\PIPE\netdfs',
        r'\PIPE\netlogon',
        r'\PIPE\ntsvcs',
        r'\PIPE\PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER',
        r'\PIPE\scerpc',
        r'\PIPE\spoolss',
        r'\PIPE\srvsvc',
        r'\PIPE\VBoxTrayIPC-Administrator',
        r'\PIPE\W32TIME_ALT',
        r'\PIPE\wkssvc'
    ]
    known_pipes += [r'\PIPE\Winsock2\CatalogChangeListener-%03x-0' % k for k in range(0x1000)]
    known_pipes += [r'\PIPE\RpcProxy\%d' % k for k in range(65536)]

    found_pipes = []
    k, maxi = 0, len(known_pipes)
    for pipe in known_pipes:
        k += 1
        print("\x1b[2K[>] (%d/%d | %5.2f %%) Trying '%s'\r" % (k, maxi, round((k/maxi) * 100, 3), pipe), end="")
        sys.stdout.flush()
        if can_connect_to_pipe(options.target, pipe, verbose=options.verbose):
            found_pipes.append(pipe)
            print('\x1b[2K - %s' % pipe)

    print("[+] Found %d pipes." % len(pipes))
    return found_pipes


def parseArgs():
    print("ListAvailablePipesOnRemoteMachine v1.2 - by @podalirius_\n")

    parser = argparse.ArgumentParser(add_help=True, description="A script to list available SMB pipes remotely on a Windows machine through the IPC$ share.")

    parser.add_argument("-u", "--username", default="", help="Username to authenticate to the endpoint.")
    parser.add_argument("-p", "--password", default="", help="Password to authenticate to the endpoint. (if omitted, it will be asked unless -no-pass is specified)")
    parser.add_argument("-d", "--domain", default="", help="Windows domain name to authenticate to the endpoint.")
    parser.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    parser.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    parser.add_argument("--target", action="store", metavar="ip address", help="Target machine.")
    parser.add_argument("--target-ip", action="store", metavar="ip address", help="IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it")
    parser.add_argument("-P", "--port", choices=["139", "445"], nargs="?", default="445", metavar="destination port", help="Destination port to connect to SMB Server")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode. (default: False)")
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
            print("[>] Listing created and deleted SMB pipes every second ... ")
            if options.username == "":
                pipes_after = bruteforce_remote_pipes(options, debug=options.verbose)
            else:
                pipes_after = list_remote_pipes(options, lmhash, nthash, debug=options.verbose)
            pipes_before = pipes_after[:]
            while True:
                time.sleep(1)
                pipes_after = list_remote_pipes(options, lmhash, nthash, debug=options.verbose)
                timenow = datetime.datetime.now().strftime("%Y-%m-%d %Hh:%Mm:%Ss")
                for pb in pipes_before:
                    if pb not in pipes_after:
                        print("[\x1b[93m%s\x1b[0m] Pipe '\x1b[94m%s\x1b[0m' was \x1b[1;91mdeleted\x1b[0m." % (timenow, pb))
                for pa in pipes_after:
                    if pa not in pipes_before:
                        print("[\x1b[93m%s\x1b[0m] Pipe '\x1b[94m%s\x1b[0m' was \x1b[1;92mcreated\x1b[0m." % (timenow, pa))
                pipes_before = pipes_after[:]
        except KeyboardInterrupt as e:
            pass
    else:
        print("[>] Listing open SMB pipes ... ")
        if options.username == "":
            pipes = bruteforce_remote_pipes(options, debug=options.verbose)
        else:
            pipes = list_remote_pipes(options, lmhash, nthash, debug=options.verbose)
            for f in pipes:
                print(' - ', f)
            print("[+] Found %d pipes." % len(pipes))

