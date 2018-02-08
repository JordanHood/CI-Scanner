import requests
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth
from optparse import OptionParser
import oauthlib
import argparse
import pprint


# py-ci -a basic -u "admin" -p "12345678" -l [list] 192.168.0.4 -h host

def main():
    testargs = ["-a", "basic", "-u", "admin", "-p", "12345678", "-l", "./wordlist", "-w", "http://192.168.0.4/cgi-bin/adv/"]
    parser = argparse.ArgumentParser()
    parser.add_argument("--auth", "-a", help="Type of authentication to use against target, default none", action="store", type=str, dest="auth")
    parser.add_argument("--username", "-u", help="Username to use on remote host", action="store", type=str, dest="user")
    parser.add_argument("--password", "-p", help="Password to use on remote host", action="store", type=str, dest="password")
    parser.add_argument("--wordlist", "-l", help="List of files to look for on remote host", action="store", type=str, dest="file")
    parser.add_argument("--host", "-w", help="Remote host to target", action="store", type=str, dest="host")
    parser.add_argument("--port", "-n", help="Port to attempt scan on", action="store", type=int, dest="port")
    parser.add_argument("--type", "-t", help="Action to carry out, search or inject, default search", action="store", type=str, dest="type")
    args = parser.parse_args(testargs)

    host = None
    port = None
    auth = None
    file = None

    if args.host:
        host = args.host
        if args.port:
            port = args.port
        else:
            port = 80
        if args.file:
            file = readfile(args.file)
        else:
            print("host missing")
    else:
        print("host missing")

    if args.auth:
        if args.user:
            if args.password:
                auth = HTTPDigestAuth(args.user, args.password)
                if args.type == "inject":
                    inject(file, host, port, auth)
                elif args.type == "search":
                    probe(file, host, auth, port)
                else:
                    search(file, host, port, auth)
                    #print("Invalid test type")
            else:
                print("password missing")
        else:
            print("username missing")


def readfile(uri):
    file = open(uri, 'r').read().splitlines()
    return file


def search(wordlist, host, port, auth=None,):

    if auth:
        results = []
        session = requests.session()
        for i in range(0, len(wordlist)):
            url = host + wordlist[i]
            response = session.get(url, auth=auth)
            results.append((response.status_code, url))
        print_results(results)


def inject():
    print("inject")


def print_results(results):
    for i, j in results:
        print(str(i) + ": " + j)


def sendrequest():
    print("todo")


if __name__ == "__main__":
    main()
