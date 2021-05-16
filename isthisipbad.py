#!/usr/bin/env python3

import os
import sys
import argparse
import socket
import dns
import warnings
from dns import resolver
from requests import get

def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text

    return '\x1b[%dm%s\x1b[0m' % (color_code, text)


def red(text):
    return color(text, 31)


def blink(text):
    return color(text, 5)


def green(text):
    return color(text, 32)


def blue(text):
    return color(text, 34)


bls = ["b.barracudacentral.org", "bl.spamcop.net",
       "blacklist.woody.ch", "cbl.abuseat.org",
       "combined.abuse.ch", "combined.rbl.msrbl.net",
       "db.wpbl.info", "dnsbl.cyberlogic.net",
       "dnsbl.sorbs.net", "drone.abuse.ch", "drone.abuse.ch",
       "duinv.aupads.org", "dul.dnsbl.sorbs.net", "dul.ru",
       "dynip.rothen.com",
       "http.dnsbl.sorbs.net", "images.rbl.msrbl.net",
       "ips.backscatterer.org", "ix.dnsbl.manitu.net",
       "korea.services.net", "misc.dnsbl.sorbs.net",
       "noptr.spamrats.com", "ohps.dnsbl.net.au", "omrs.dnsbl.net.au",
       "osps.dnsbl.net.au", "osrs.dnsbl.net.au",
       "owfs.dnsbl.net.au", "pbl.spamhaus.org", "phishing.rbl.msrbl.net",
       "probes.dnsbl.net.au", "proxy.bl.gweep.ca", "rbl.interserver.net",
       "rdts.dnsbl.net.au", "relays.bl.gweep.ca", "relays.nether.net",
       "residential.block.transip.nl", "ricn.dnsbl.net.au",
       "rmst.dnsbl.net.au", "smtp.dnsbl.sorbs.net",
       "socks.dnsbl.sorbs.net", "spam.abuse.ch", "spam.dnsbl.sorbs.net",
       "spam.rbl.msrbl.net", "spam.spamrats.com", "spamrbl.imp.ch",
       "t3direct.dnsbl.net.au", "tor.dnsbl.sectoor.de",
       "torserver.tor.dnsbl.sectoor.de", "ubl.lashback.com",
       "ubl.unsubscore.com", "virus.rbl.jp", "virus.rbl.msrbl.net",
       "web.dnsbl.sorbs.net", "wormrbl.imp.ch", "xbl.spamhaus.org",
       "zen.spamhaus.org", "zombie.dnsbl.sorbs.net"]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Is This IP Bad?')
    parser.add_argument('-i', '--ip', help='IP address to check')
    args = parser.parse_args()

    if args is not None and args.ip is not None and len(args.ip) > 0:
        badip = args.ip
    else:
        my_ip = get('https://api.ipify.org').text
        print(blue('Check IP against popular IP and DNS blacklists'))
        print(blue('A quick and dirty script by @jgamblin\n'))
        print(red('Your public IP address is {0}\n'.format(my_ip)))

        # Get IP To Check
        resp = input('Would you like to check {0} ? (Y/N):'.format(my_ip))

        if resp.lower() in ["yes", "y"]:
            badip = my_ip
        else:
            badip = input(blue("\nWhat IP would you like to check?: "))
            if badip is None or badip == "":
                sys.exit("No IP address to check.")

    #IP INFO
    reversed_dns = socket.getfqdn(badip)
    geoip = get('http://api.hackertarget.com/geoip/?q='
                           + badip).text

    print(blue('\nThe FQDN for {0} is {1}\n'.format(badip, reversed_dns)))
    print(red('Geolocation IP Information:'))
    print(blue(geoip))
    print('\n')

    BAD = 0
    GOOD = 0

    for bl in bls:
        try:
                my_resolver = dns.resolver.Resolver()
                query = '.'.join(reversed(str(badip).split("."))) + "." + bl
                my_resolver.timeout = 5
                my_resolver.lifetime = 5
                answers = my_resolver.query(query, "A")
                answer_txt = my_resolver.query(query, "TXT")
                print(red(badip + ' is listed in ' + bl)
                       + ' (%s: %s)' % (answers[0], answer_txt[0]))
                BAD = BAD + 1

        except dns.resolver.NXDOMAIN:
            print(green(badip + ' is not listed in ' + bl))
            GOOD = GOOD + 1

        except dns.resolver.Timeout:
            print(blink('WARNING: Timeout querying ' + bl))

        except dns.resolver.NoNameservers:
            print(blink('WARNING: No nameservers for ' + bl))

        except dns.resolver.NoAnswer:
             print(blink('WARNING: No answer for ' + bl))

    print(red('\n{0} is on {1}/{2} blacklists.\n'.format(badip, BAD, (GOOD+BAD))))
