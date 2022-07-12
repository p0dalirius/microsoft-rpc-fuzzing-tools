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


def parseArgs():
    print("ListAvailablePipesOnRemoteMachine v1.1 - by @podalirius_\n")

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
        pipes = list_remote_pipes(options, lmhash, nthash, debug=options.verbose)
        for f in pipes:
            print(' - ', f)
        print("[+] Found %d pipes." % len(pipes))