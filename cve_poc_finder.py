#! /usr/bin/python3

import requests as req
import json
import argparse
from colorama import Fore, Back, Style

def banner():

    print(Fore.RED+r"""
____ _  _ ____ _  _ ____ _ _ _ _  _ 
|    |  | |___ |__| |__| | | | |_/  
|___  \/  |___ |  | |  | |_|_| | \_ 
                                    
    """+Fore.RESET)


arg_parser = argparse.ArgumentParser(description="CVE PoC Finder")
arg_parser.add_argument("-c", "--cve", help="input target cve id", required=True, type=str, metavar="")
arg_parser.add_argument("--silent", help="silent mode", required=False, action="store_true")
args = arg_parser.parse_args()
cve_id = args.cve

if not args.silent:
    banner()

print(Fore.GREEN+"[*] Searching for PoC's for CVE: "+cve_id+Fore.RESET)