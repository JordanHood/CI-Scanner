#!/usr/bin/python3.6
import requests
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth
#from optparse import OptionParser
#import oauthlib
import argparse
import socket
import sys
from time import sleep


# py-ci -a basic -u "admin" -p "12345678" -l [list] 192.168.0.4 -h host

def main():
    # testargs = ["-t", "search",  "-a", "basic", "-u", "root", "-p", "root", "-l", "wordlists/wordlist", "-w", "http://192.168.0.200/cgi-bin/admin/"]
    parser = argparse.ArgumentParser()
    parser.add_argument("--auth", "-a", help="Type of authentication to use against target, default none", action="store", type=str, dest="auth")
    parser.add_argument("--username", "-u", help="Username to use on remote host", action="store", type=str, dest="user")
    parser.add_argument("--password", "-p", help="Password to use on remote host", action="store", type=str, dest="password")
    parser.add_argument("--wordlist", "-l", help="List of files to look for on remote host", action="store", type=str, dest="file")
    parser.add_argument("--host", "-w", help="Remote host to target", action="store", type=str, dest="host")
    parser.add_argument("--port", "-n", help="Port to attempt scan on", action="store", type=int, dest="port")
    parser.add_argument("--type", "-t", help="Action to carry out, search or inject, default search", action="store", type=str, dest="type")
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()
    else: 
        args = parser.parse_args()
        start(args)

def start(args):

    #check for host
    if args.host:
        host = args.host
    else:
        print("ERROR: No target host specified")
        sys.exit(1)

    # check for port else set to 80
    if args.port:
        port = args.port
    else:
        port = 80

    #check for word list file
    if args.file:
        try:
            file = open(args.file, 'r').read().splitlines()
        except FileNotFoundError:
            print("ERROR: Failed to find " + args.file)
            sys.exit(1)

    if args.auth:
        if args.user is None:
            print("ERROR: No username specified")
            sys.exit(1)
        if args.password is None:
            print("ERROR: No username specified")
            sys.exit(1)
        if args.auth == "basic":
            auth = HTTPBasicAuth(args.user, args.password)
        elif args.auth == "digest":
            auth = HTTPDigestAuth()
        else:
            print("ERROR: Unknown auth type " + args.auth)
            sys.exit(1)

    if args.type:
        if args.type == "inject":
            inject(file, host, port, auth)
        elif args.type == "search":
            search(file, host, port, auth)
    else:
        print("ERROR: No type specified")
        sys.exit(1)


def readfile(uri):
    try:
        file = open(uri, 'r').read().splitlines()
        return file
    except FileNotFoundError:
        print("Error File not found")
        sys.exit(1)



def search(wordlist, host, port, auth=None,):

    if auth:
        results = []
        session = requests.session()
        for i in range(0, len(wordlist)):
            url = host + wordlist[i]
            try:
                response = session.get(url, auth=auth)
                results.append((response.status_code, url))
                sleep(0.5) # sleep for half second so we dont overload the device
            except requests.exceptions.ConnectionError:
                results.append(("Connection refused", url))
        print_results(results)


def listen():

    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_socket.settimeout(5)

    try:
        count = 0
        while count < 3:
            print("listening")
            data = icmp_socket.recv(1024)
            header = data[:20]
            ip = header[-8:-4]
            print(str(ip[0]) + "." + str(ip[1]) + "." + str(ip[2]) + "." + str(ip[3]))

    except socket.timeout:
        print("Timed out waiting")


def inject():
    print("inject")


def print_results(results):
    for i, j in results:
        print(str(i) + ": " + j)


def sendrequest():
    print("todo")


if __name__ == "__main__":
    main()
