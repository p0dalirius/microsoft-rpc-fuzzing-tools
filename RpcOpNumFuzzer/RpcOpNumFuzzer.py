#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : OpNumFuzzer.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 Jan 2023


import sys
import argparse
from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'SessionError: unknown error code: 0x%x' % self.error_code


class Request(NDRCALL):
    opnum = 4
    structure = ()


class Response(NDRCALL):
    structure = ()


class OpNumFuzzer(object):
    uuid = None
    version = None
    pipe = None

    ncan_target = None
    __rpctransport = None
    dce = None

    def __init__(self):
        super(OpNumFuzzer, self).__init__()

    def connect(self, username, password, domain, lmhash, nthash, target, kdcHost, doKerberos=False, targetIp=None):
        self.ncan_target = r'ncacn_np:%s[%s]' % (target, self.pipe)
        self.__rpctransport = transport.DCERPCTransportFactory(self.ncan_target)

        if hasattr(self.__rpctransport, 'set_credentials'):
            self.__rpctransport.set_credentials(
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash
            )

        if doKerberos == True:
            self.__rpctransport.set_kerberos(doKerberos, kdcHost=kdcHost)
        # if targetIp is not None:
        #     self.__rpctransport.setRemoteHost(targetIp)

        self.dce = self.__rpctransport.get_dce_rpc()
        self.dce.set_auth_type(RPC_C_AUTHN_WINNT)
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        print("[>] Connecting to %s ... " % self.ncan_target, end="")
        sys.stdout.flush()
        try:
            self.dce.connect()
        except Exception as e:
            print("\x1b[1;91mfail\x1b[0m")
            print("[!] Something went wrong, check error status => %s" % str(e))
            return False
        else:
            print("\x1b[1;92msuccess\x1b[0m")

        print("[>] Binding to <uuid='%s', version='%s'> ... " % (self.uuid, self.version), end="")
        sys.stdout.flush()
        try:
            self.dce.bind(uuidtup_to_bin((self.uuid, self.version)))
        except Exception as e:
            print("\x1b[1;91mfail\x1b[0m")
            print("[!] Something went wrong, check error status => %s" % str(e))
            return False
        else:
            print("\x1b[1;92msuccess\x1b[0m")

        return True

    def test(self, opnum):
        if self.dce is not None:
            try:
                req = Request()
                req.opnum = opnum
                resp = self.dce.request(req)
            except Exception as err:
                return str(err)
        else:
            print("[!] Error: dce is None, you must call connect() first.")


def parseArgs():
    print("OpNum Fuzzer\n")

    parser = argparse.ArgumentParser(add_help=True, description="smbclient-ng, a fast and user friendly way to interact with SMB shares.")
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode.")
    parser.add_argument("--no-colors", dest="no_colors", action="store_true", default=False, help="No colors mode.")

    group_target = parser.add_argument_group("Target")
    group_target.add_argument("--host", action="store", metavar="HOST", required=True, type=str, help="IP address or hostname of the SMB Server to connect to.")  
    group_target.add_argument("--port", action="store", metavar="PORT", type=int, default=445, help="Port of the SMB Server to connect to. (default: 445)")

    authconn = parser.add_argument_group("Authentication & connection")
    authconn.add_argument("--kdcHost", dest="kdcHost", action="store", metavar="FQDN KDC", help="FQDN of KDC for Kerberos.")
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", default='.', help="(FQDN) domain to authenticate to.")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="User to authenticate with.")

    secret = parser.add_argument_group()
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k).")
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", nargs="?", help="Password to authenticate with.")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help="NT/LM hashes, format is LMhash:NThash.")
    cred.add_argument("--aes-key", dest="aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits).")
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line.")

    parser.add_argument("--uuid", dest="uuid", required=True, help="RPC Interface UUID.")
    parser.add_argument("--version", dest="version", required=True, help="RPC Interface Version.")
    parser.add_argument("--pipe", dest="pipe", required=True, help="SMB pipe.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.auth_username is not None and (options.auth_password is None and options.no_pass == False and options.auth_hashes is None):
        print("[+] No password or hashes provided and --no-pass is '%s'" % options.no_pass)
        from getpass import getpass
        if options.auth_domain is not None:
            options.auth_password = getpass("  | Provide a password for '%s\\%s':" % (options.auth_domain, options.auth_username))
        else:
            options.auth_password = getpass("  | Provide a password for '%s':" % options.auth_username)

    # Use AES Authentication key if available
    if options.aesKey is not None:
        options.use_kerberos = True
    if options.use_kerberos is True and options.kdcHost is None:
        print("[!] Specify KDC's Hostname of FQDN using the argument --kdcHost")
        exit()
    
    # Parse hashes
    if options.auth_hashes is not None:
        if ":" not in options.auth_hashes:
            options.auth_hashes = ":" + options.auth_hashes

    return options


if __name__ == '__main__':
    options = parseArgs()

    fuzzer = OpNumFuzzer()

    fuzzer.uuid = options.uuid
    fuzzer.version = options.version
    fuzzer.pipe = options.pipe

    connected = fuzzer.connect(
        username=options.auth_username,
        password=options.auth_password,
        domain=options.auth_domain,
        lmhash="",
        nthash="",
        target=options.host,
        doKerberos=options.use_kerberos,
        kdcHost=options.kdcHost,
        targetIp=options.host
    )

    if connected:
        for opnum in range(30):
            result = fuzzer.test(opnum)

            if result == "rpc_x_bad_stub_data":
                print("\x1b[1;92m[+] [%3d] OpNum exists.\x1b[0m" % opnum)
                
            elif result == "nca_s_op_rng_error":
                print("\x1b[1;91m[-] [%3d] OpNum does not exist.\x1b[0m" % opnum)

    sys.exit()