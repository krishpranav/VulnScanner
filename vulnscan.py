#!/usr/bin/python
# -*- coding: utf-8 -*-
#                               __         __
#                              /__)_   '_/(  _ _
#                             / ( (//)/(/__)( (//)
#                                  /
#
# Author	 : Shankar Damodaran
# Tool 		 : RapidScan
# Usage		 : ./rapidscan.py example.com (or) python rapidsan.py example.com
# Description: This scanner automates the process of security scanning by using a
#              multitude of available linux security tools and some custom scripts.
#

# Importing the libraries
import sys
import socket
import subprocess
import os
import time
import signal
import random
import string
import threading
import re
from urlparse import urlsplit



# Scan Time Elapser
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


def url_maker(url):
	if not re.match(r'http(s?)\:', url):
		url = 'http://' + url
	parsed = urlsplit(url)
	host = parsed.netloc
	if host.startswith('www.'):
		host = host[4:]
	return host

def check_internet():
    os.system('ping -c1 github.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val


# Initializing the color module class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT 	= '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'


# Classifies the Vulnerability's Severity
def vul_info(val):
	result =''
	if val == 'c':
		result = bcolors.BG_CRIT_TXT+" critical "+bcolors.ENDC
	elif val == 'h':
		result = bcolors.BG_HIGH_TXT+" high "+bcolors.ENDC
	elif val == 'm':
		result = bcolors.BG_MED_TXT+" medium "+bcolors.ENDC
	elif val == 'l':
		result = bcolors.BG_LOW_TXT+" low "+bcolors.ENDC
	else:
		result = bcolors.BG_INFO_TXT+" info "+bcolors.ENDC
	return result

# Legends
proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC

# Links the vulnerability with threat level and remediation database
def vul_remed_info(v1,v2,v3):
	print bcolors.BOLD+"Vulnerability Threat Level"+bcolors.ENDC
	print "\t"+vul_info(v2)+" "+bcolors.WARNING+str(tool_resp[v1][0])+bcolors.ENDC
	print bcolors.BOLD+"Vulnerability Definition"+bcolors.ENDC
	print "\t"+bcolors.BADFAIL+str(tools_fix[v3-1][1])+bcolors.ENDC
	print bcolors.BOLD+"Vulnerability Remediation"+bcolors.ENDC
	print "\t"+bcolors.OKGREEN+str(tools_fix[v3-1][2])+bcolors.ENDC


# RapidScan Help Context
def helper():
        print bcolors.OKBLUE+"Information:"+bcolors.ENDC
        print "------------"
        print "\t./vulnscan.py example.com: Scans the domain example.com"
        print "\t./vulnscan.py --update   : Updates the scanner to the latest version."
        print "\t./vulnscan.py --help     : Displays this help context."
        print bcolors.OKBLUE+"Interactive:"+bcolors.ENDC
        print "------------"
        print "\tCtrl+C: Skips current test."
        print "\tCtrl+Z: Quits vulnscan."
        print bcolors.OKBLUE+"Legends:"+bcolors.ENDC
        print "--------"
        print "\t["+proc_high+"]: Scan process may take longer times (not predictable)."
        print "\t["+proc_med+"]: Scan process may take less than 10 minutes."
        print "\t["+proc_low+"]: Scan process may take less than a minute or two."
        print bcolors.OKBLUE+"Vulnerability Information:"+bcolors.ENDC
        print "--------------------------"
        print "\t"+vul_info('c')+": Requires immediate attention as it may lead to compromise or service unavailability."
        print "\t"+vul_info('h')+"    : May not lead to an immediate compromise, but there are high chances of probability."
        print "\t"+vul_info('m')+"  : Attacker may correlate multiple vulnerabilities of this type to launch a sophisticated attack."
        print "\t"+vul_info('l')+"     : Not a serious issue, but it is recommended to attend the finding."
        print "\t"+vul_info('i')+"    : Not classified as a vulnerability, simply an useful informational alert to be considered.\n"


# Clears Line
def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K")





# Initiliazing the idle loader/spinner class
class Spinner:
    busy = False
    delay = 0.05

    @staticmethod
    def spinning_cursor():
        while 1:
            for cursor in '|/\\': yield cursor #←↑↓→
            #for cursor in '←↑↓→': yield cursor
    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay

    def spinner_task(self):
        try:
            while self.busy:

                print bcolors.BG_ERR_TXT+next(self.spinner_generator)+bcolors.ENDC,
                sys.stdout.flush()
                time.sleep(self.delay)
                sys.stdout.write('\b')
                sys.stdout.flush()
        except (KeyboardInterrupt, SystemExit):
            #clear()
            print "\n\t"+ bcolors.BG_ERR_TXT+"VulnScan received a series of Ctrl+C  Quitting..." +bcolors.ENDC
            sys.exit(1)

    def start(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            #clear()
            print "\n\t"+ bcolors.BG_ERR_TXT+"RapidScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC
            sys.exit(1)

spinner = Spinner()



tool_names = [
                ["host","Host - Checks for existence of IPV6 address.","host",1],
                ["aspnet_config_err","ASP.Net Misconfiguration - Checks for ASP.Net Misconfiguration.","wget",1],
                ["wp_check","WordPress Checker - Checks for WordPress Installation.","wget",1],
                ["drp_check", "Drupal Checker - Checks for Drupal Installation.","wget",1],
                ["joom_check", "Joomla Checker - Checks for Joomla Installation.","wget",1],
                ["uniscan","Uniscan - Checks for robots.txt & sitemap.xml","uniscan",1],
                ["wafw00f","Wafw00f - Checks for Application Firewalls.","wafw00f",1],
                ["nmap","Nmap - Fast Scan [Only Few Port Checks]","nmap",1],
                ["theHarvester","The Harvester - Scans for emails using Google's passive search.","theHarvester",1],
                ["dnsrecon","DNSRecon - Attempts Multiple Zone Transfers on Nameservers.","dnsrecon",1],
                ["fierce","Fierce - Attempts Zone Transfer [No Brute Forcing]","fierce",1],
                ["dnswalk","DNSWalk - Attempts Zone Transfer.","dnswalk",1],
                ["whois","WHOis - Checks for Administrator's Contact Information.","whois",1],
                ["nmap_header","Nmap [XSS Filter Check] - Clohecks if XSS Protection Header is present.","nmap",1],
                ["nmap_sloris","Nmap [Slowloris DoS] - Checks for Slowloris Denial of Service Vulnerability.","nmap",1],
                ["sslyze_hbleed","SSLyze - Checks only for Heartbleed Vulnerability.","sslyze",1],
                ["nmap_hbleed","Nmap [Heartbleed] - Checks only for Heartbleed Vulnerability.","nmap",1],
                ["nmap_poodle","Nmap [POODLE] - Checks only for Poodle Vulnerability.","nmap",1],
                ["nmap_ccs","Nmap [OpenSSL CCS Injection] - Checks only for CCS Injection.","nmap",1],
                ["nmap_freak","Nmap [FREAK] - Checks only for FREAK Vulnerability.","nmap",1],
                ["nmap_logjam","Nmap [LOGJAM] - Checks for LOGJAM Vulnerability.","nmap",1],
                ["sslyze_ocsp","SSLyze - Checks for OCSP Stapling.","sslyze",1],
                ["sslyze_zlib","SSLyze - Checks for ZLib Deflate Compression.","sslyze",1],
                ["sslyze_reneg","SSLyze - Checks for Secure Renegotiation Support and Client Renegotiation.","sslyze",1],
                ["sslyze_resum","SSLyze - Checks for Session Resumption Support with [Session IDs/TLS Tickets].","sslyze",1],
                ["lbd","LBD - Checks for DNS/HTTP Load Balancers.","lbd",1],
                ["golismero_dns_malware","Golismero - Checks if the domain is spoofed or hijacked.","golismero",1],
                ["golismero_heartbleed","Golismero - Checks only for Heartbleed Vulnerability.","golismero",1],
                ["golismero_brute_url_predictables","Golismero - BruteForces for certain files on the Domain.","golismero",1],
                ["golismero_brute_directories","Golismero - BruteForces for certain directories on the Domain.","golismero",1],
                ["golismero_sqlmap","Golismero - SQLMap [Retrieves only the DB Banner]","golismero",1],
                ["dirb","DirB - Brutes the target for Open Directories.","dirb",1],
                ["xsser","XSSer - Checks for Cross-Site Scripting [XSS] Attacks.","xsser",1],
                ["golismero_ssl_scan","Golismero SSL Scans - Performs SSL related Scans.","golismero",1],
                ["golismero_zone_transfer","Golismero Zone Transfer - Attempts Zone Transfer.","golismero",1],
                ["golismero_nikto","Golismero Nikto Scans - Uses Nikto Plugin to detect vulnerabilities.","golismero",1],
                ["golismero_brute_subdomains","Golismero Subdomains Bruter - Brute Forces Subdomain Discovery.","golismero",1],
                ["dnsenum_zone_transfer","DNSEnum - Attempts Zone Transfer.","dnsenum",1],
                ["fierce_brute_subdomains","Fierce Subdomains Bruter - Brute Forces Subdomain Discovery.","fierce",1],
                ["dmitry_email","DMitry - Passively Harvests Emails from the Domain.","dmitry",1],
                ["dmitry_subdomains","DMitry - Passively Harvests Subdomains from the Domain.","dmitry",1],
                ["nmap_telnet","Nmap [TELNET] - Checks if TELNET service is running.","nmap",1],
                ["nmap_ftp","Nmap [FTP] - Checks if FTP service is running.","nmap",1],
                ["nmap_stuxnet","Nmap [STUXNET] - Checks if the host is affected by STUXNET Worm.","nmap",1],
                ["webdav","WebDAV - Checks if WEBDAV enabled on Home directory.","davtest",1],
                ["golismero_finger","Golismero - Does a fingerprint on the Domain.","golismero",1],
                ["uniscan_filebrute","Uniscan - Brutes for Filenames on the Domain.","uniscan",1],
                ["uniscan_dirbrute", "Uniscan - Brutes Directories on the Domain.","uniscan",1],
                ["uniscan_ministresser", "Uniscan - Stress Tests the Domain.","uniscan",1],
                ["uniscan_rfi","Uniscan - Checks for LFI, RFI and RCE.","uniscan",1],#50
                ["uniscan_xss","Uniscan - Checks for XSS, SQLi, BSQLi & Other Checks.","uniscan",1],
                ["nikto_xss","Nikto - Checks for Apache Expect XSS Header.","nikto",1],
                ["nikto_subrute","Nikto - Brutes Subdomains.","nikto",1],
                ["nikto_shellshock","Nikto - Checks for Shellshock Bug.","nikto",1],
                ["nikto_internalip","Nikto - Checks for Internal IP Leak.","nikto",1],
                ["nikto_putdel","Nikto - Checks for HTTP PUT DEL.","nikto",1],
                ["nikto_headers","Nikto - Checks the Domain Headers.","nikto",1],
                ["nikto_ms01070","Nikto - Checks for MS10-070 Vulnerability.","nikto",1],
                ["nikto_servermsgs","Nikto - Checks for Server Issues.","nikto",1],
                ["nikto_outdated","Nikto - Checks if Server is Outdated.","nikto",1],
                ["nikto_httpoptions","Nikto - Checks for HTTP Options on the Domain.","nikto",1],
                ["nikto_cgi","Nikto - Enumerates CGI Directories.","nikto",1],
                ["nikto_ssl","Nikto - Performs SSL Checks.","nikto",1],
                ["nikto_sitefiles","Nikto - Checks for any interesting files on the Domain.","nikto",1],
                ["nikto_paths","Nikto - Checks for Injectable Paths.","nikto",1],
                ["dnsmap_brute","DNSMap - Brutes Subdomains.","dnsmap",1],
                ["nmap_sqlserver","Nmap - Checks for MS-SQL Server DB","nmap",1],
                ["nmap_mysql", "Nmap - Checks for MySQL DB","nmap",1],
                ["nmap_oracle", "Nmap - Checks for ORACLE DB","nmap",1],
                ["nmap_rdp_udp","Nmap - Checks for Remote Desktop Service over UDP","nmap",1],
                ["nmap_rdp_tcp","Nmap - Checks for Remote Desktop Service over TCP","nmap",1],
                ["nmap_full_ps_tcp","Nmap - Performs a Full TCP Port Scan","nmap",1],
                ["nmap_full_ps_udp","Nmap - Performs a Full UDP Port Scan","nmap",1],
                ["nmap_snmp","Nmap - Checks for SNMP Service","nmap",1],
                ["aspnet_elmah_axd","Checks for ASP.net Elmah Logger","wget",1],
                ["nmap_tcp_smb","Checks for SMB Service over TCP","nmap",1],
                ["nmap_udp_smb","Checks for SMB Service over UDP","nmap",1],
                ["wapiti","Wapiti - Checks for SQLi, RCE, XSS and Other Vulnerabilities","wapiti",1],
                ["nmap_iis","Nmap - Checks for IIS WebDAV","nmap",1],
                ["whatweb","WhatWeb - Checks for X-XSS Protection Header","whatweb",1]
            ]


# Command that is used to initiate the tool (with parameters and extra params)
tool_cmd   = [
                ["host ",""],
                ["wget -O temp_aspnet_config_err --tries=1 ","/%7C~.aspx"],
                ["wget -O temp_wp_check --tries=1 ","/wp-admin"],
                ["wget -O temp_drp_check --tries=1 ","/user"],
                ["wget -O temp_joom_check --tries=1 ","/administrator"],
                ["uniscan -e -u ",""],
                ["wafw00f ",""],
                ["nmap -F --open -Pn ",""],
                ["theHarvester -l 50 -b google -d ",""],
                ["dnsrecon -d ",""],
                ["fierce -wordlist xxx -dns ",""],
                ["dnswalk -d ","."],
                ["whois ",""],
                ["nmap -p80 --script http-security-headers -Pn ",""],
                ["nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn ",""],
                ["sslyze --heartbleed ",""],
                ["nmap -p443 --script ssl-heartbleed -Pn ",""],
                ["nmap -p443 --script ssl-poodle -Pn ",""],
                ["nmap -p443 --script ssl-ccs-injection -Pn ",""],
                ["nmap -p443 --script ssl-enum-ciphers -Pn ",""],
                ["nmap -p443 --script ssl-dh-params -Pn ",""],
                ["sslyze --certinfo=basic ",""],
                ["sslyze --compression ",""],
                ["sslyze --reneg ",""],
                ["sslyze --resum ",""],
                ["lbd ",""],
                ["golismero -e dns_malware scan ",""],
                ["golismero -e heartbleed scan ",""],
                ["golismero -e brute_url_predictables scan ",""],
                ["golismero -e brute_directories scan ",""],
                ["golismero -e sqlmap scan ",""],
                ["dirb http://"," -fi"],
                ["xsser --all=http://",""],
                ["golismero -e sslscan scan ",""],
                ["golismero -e zone_transfer scan ",""],
                ["golismero -e nikto scan ",""],
                ["golismero -e brute_dns scan ",""],
                ["dnsenum ",""],
                ["fierce -dns ",""],
                ["dmitry -e ",""],
                ["dmitry -s ",""],
                ["nmap -p23 --open -Pn ",""],
                ["nmap -p21 --open -Pn ",""],
                ["nmap --script stuxnet-detect -p445 -Pn ",""],
                ["davtest -url http://",""],
                ["golismero -e fingerprint_web scan ",""],
                ["uniscan -w -u ",""],
                ["uniscan -q -u ",""],
                ["uniscan -r -u ",""],
                ["uniscan -s -u ",""],
                ["uniscan -d -u ",""],
                ["nikto -Plugins 'apache_expect_xss' -host ",""],
                ["nikto -Plugins 'subdomain' -host ",""],
                ["nikto -Plugins 'shellshock' -host ",""],
                ["nikto -Plugins 'cookies' -host ",""],
                ["nikto -Plugins 'put_del_test' -host ",""],
                ["nikto -Plugins 'headers' -host ",""],
                ["nikto -Plugins 'ms10-070' -host ",""],
                ["nikto -Plugins 'msgs' -host ",""],
                ["nikto -Plugins 'outdated' -host ",""],
                ["nikto -Plugins 'httpoptions' -host ",""],
                ["nikto -Plugins 'cgi' -host ",""],
                ["nikto -Plugins 'ssl' -host ",""],
                ["nikto -Plugins 'sitefiles' -host ",""],
                ["nikto -Plugins 'paths' -host ",""],
                ["dnsmap ",""],
                ["nmap -p1433 --open -Pn ",""],
                ["nmap -p3306 --open -Pn ",""],
                ["nmap -p1521 --open -Pn ",""],
                ["nmap -p3389 --open -sU -Pn ",""],
                ["nmap -p3389 --open -sT -Pn ",""],
                ["nmap -p1-65535 --open -Pn ",""],
                ["nmap -p1-65535 -sU --open -Pn ",""],
                ["nmap -p161 -sU --open -Pn ",""],
                ["wget -O temp_aspnet_elmah_axd --tries=1 ","/elmah.axd"],
                ["nmap -p445,137-139 --open -Pn ",""],
                ["nmap -p137,138 --open -Pn ",""],
                ["wapiti "," -f txt -o temp_wapiti"],
                ["nmap -p80 --script=http-iis-webdav-vuln -Pn ",""],
                ["whatweb "," -a 1"]
            ]


# Tool Responses (Begins) [Responses + Severity (c - critical | h - high | m - medium | l - low | i - informational) + Reference for Vuln Definition and Remediation]
tool_resp   = [
                ["Does not have an IPv6 Address. It is good to have one.","i",1],
                ["ASP.Net is misconfigured to throw server stack errors on screen.","m",2],
                ["WordPress Installation Found. Check for vulnerabilities corresponds to that version.","i",3],
                ["Drupal Installation Found. Check for vulnerabilities corresponds to that version.","i",4],
                ["Joomla Installation Found. Check for vulnerabilities corresponds to that version.","i",5],
                ["robots.txt/sitemap.xml found. Check those files for any information.","i",6],
                ["No Web Application Firewall Detected","m",7],
                ["Some ports are open. Perform a full-scan manually.","l",8],
                ["Email Addresses Found.","l",9],
                ["Zone Transfer Successful using DNSRecon. Reconfigure DNS immediately.","h",10],
                ["Zone Transfer Successful using fierce. Reconfigure DNS immediately.","h",10],
                ["Zone Transfer Successful using dnswalk. Reconfigure DNS immediately.","h",10],
                ["Whois Information Publicly Available.","i",11],
                ["XSS Protection Filter is Disabled.","m",12],
                ["Vulnerable to Slowloris Denial of Service.","c",13],
                ["HEARTBLEED Vulnerability Found with SSLyze.","h",14],
                ["HEARTBLEED Vulnerability Found with Nmap.","h",14],
                ["POODLE Vulnerability Detected.","h",15],
                ["OpenSSL CCS Injection Detected.","h",16],
                ["FREAK Vulnerability Detected.","h",17],
                ["LOGJAM Vulnerability Detected.","h",18],
                ["Unsuccessful OCSP Response.","m",19],
                ["Server supports Deflate Compression.","m",20],
                ["Secure Renegotiation is unsupported.","m",21],
                ["Secure Resumption unsupported with (Sessions IDs/TLS Tickets).","m",22],
                ["No DNS/HTTP based Load Balancers Found.","l",23],
                ["Domain is spoofed/hijacked.","h",24],
                ["HEARTBLEED Vulnerability Found with Golismero.","h",14],
                ["Open Files Found with Golismero BruteForce.","m",25],
                ["Open Directories Found with Golismero BruteForce.","m",26],
                ["DB Banner retrieved with SQLMap.","l",27],
                ["Open Directories Found with DirB.","m",26],
                ["XSSer found XSS vulnerabilities.","c",28],
                ["Found SSL related vulnerabilities with Golismero.","m",29],
                ["Zone Transfer Successful with Golismero. Reconfigure DNS immediately.","h",10],
                ["Golismero Nikto Plugin found vulnerabilities.","m",30],
                ["Found Subdomains with Golismero.","m",31],
                ["Zone Transfer Successful using DNSEnum. Reconfigure DNS immediately.","h",10],
                ["Found Subdomains with Fierce.","m",31],
                ["Email Addresses discovered with DMitry.","l",9],
                ["Subdomains discovered with DMitry.","m",31],
                ["Telnet Service Detected.","h",32],
                ["FTP Service Detected.","c",33],
                ["Vulnerable to STUXNET.","c",34],
                ["WebDAV Enabled.","m",35],
                ["Found some information through Fingerprinting.","l",36],
                ["Open Files Found with Uniscan.","m",25],
                ["Open Directories Found with Uniscan.","m",26],
                ["Vulnerable to Stress Tests.","h",37],
                ["Uniscan detected possible LFI, RFI or RCE.","h",38],
                ["Uniscan detected possible XSS, SQLi, BSQLi.","h",39],
                ["Apache Expect XSS Header not present.","m",12],
                ["Found Subdomains with Nikto.","m",31],
                ["Webserver vulnerable to Shellshock Bug.","c",40],
                ["Webserver leaks Internal IP.","l",41],
                ["HTTP PUT DEL Methods Enabled.","m",42],
                ["Some vulnerable headers exposed.","m",43],
                ["Webserver vulnerable to MS10-070.","h",44],
                ["Some issues found on the Webserver.","m",30],
                ["Webserver is Outdated.","h",45],
                ["Some issues found with HTTP Options.","l",42],
                ["CGI Directories Enumerated.","l",26],
                ["Vulnerabilities reported in SSL Scans.","m",29],
                ["Interesting Files Detected.","m",25],
                ["Injectable Paths Detected.","l",46],
                ["Found Subdomains with DNSMap.","m",31],
                ["MS-SQL DB Service Detected.","l",47],
                ["MySQL DB Service Detected.","l",47],
                ["ORACLE DB Service Detected.","l",47],
                ["RDP Server Detected over UDP.","h",48],
                ["RDP Server Detected over TCP.","h",48],
                ["TCP Ports are Open","l",8],
                ["UDP Ports are Open","l",8],
                ["SNMP Service Detected.","m",49],
                ["Elmah is Configured.","m",50],
                ["SMB Ports are Open over TCP","m",51],
                ["SMB Ports are Open over UDP","m",51],
                ["Wapiti discovered a range of vulnerabilities","h",30],
                ["IIS WebDAV is Enabled","m",35],
                ["X-XSS Protection is not Present","m",12]



            ]

tool_status = [
                ["has IPv6",1,proc_low," < 15s","ipv6",["not found","has IPv6"]],
                ["Server Error",0,proc_low," < 30s","asp.netmisconf",["unable to resolve host address","Connection timed out"]],
                ["wp-login",0,proc_low," < 30s","wpcheck",["unable to resolve host address","Connection timed out"]],
                ["drupal",0,proc_low," < 30s","drupalcheck",["unable to resolve host address","Connection timed out"]],
                ["joomla",0,proc_low," < 30s","joomlacheck",["unable to resolve host address","Connection timed out"]],
                ["[+]",0,proc_low," < 40s","robotscheck",["Use of uninitialized value in unpack at"]],
                ["No WAF",0,proc_low," < 45s","wafcheck",["appears to be down"]],
                ["tcp open",0,proc_med," <  2m","nmapopen",["Failed to resolve"]],
                ["No emails found",1,proc_med," <  3m","harvester",["No hosts found","No emails found"]],
                ["[+] Zone Transfer was successful!!",0,proc_low," < 20s","dnsreconzt",["Could not resolve domain"]],
                ["Whoah, it worked",0,proc_low," < 30s","fiercezt",["none"]],
                ["0 errors",0,proc_low," < 35s","dnswalkzt",["!!!0 failures, 0 warnings, 3 errors."]],
                ["Admin Email:",0,proc_low," < 25s","whois",["No match for domain"]],
                ["XSS filter is disabled",0,proc_low," < 20s","nmapxssh",["Failed to resolve"]],
                ["VULNERABLE",0,proc_high," < 45m","nmapdos",["Failed to resolve"]],
                ["Server is vulnerable to Heartbleed",0,proc_low," < 40s","sslyzehb",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 30s","nmap1",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 35s","nmap2",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 35s","nmap3",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 30s","nmap4",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 35s","nmap5",["Failed to resolve"]],
                ["ERROR - OCSP response status is not successful",0,proc_low," < 25s","sslyze1",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 30s","sslyze2",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 25s","sslyze3",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 30s","sslyze4",["Could not resolve hostname"]],
                ["does NOT use Load-balancing",0,proc_med," <  4m","lbd",["NOT FOUND"]],
                ["No vulnerabilities found",1,proc_low," < 45s","golism1",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 40s","golism2",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 45s","golism3",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 40s","golism4",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 45s","golism5",["Cannot resolve domain name","No vulnerabilities found"]],
                ["FOUND: 0",1,proc_high," < 35m","dirb",["COULDNT RESOLVE HOST","FOUND: 0"]],
                ["Could not find any vulnerability!",1,proc_med," <  4m","xsser",["XSSer is not working propertly!","Could not find any vulnerability!"]],
                ["Occurrence ID",0,proc_low," < 45s","golism6",["Cannot resolve domain name"]],
                ["DNS zone transfer successful",0,proc_low," < 30s","golism7",["Cannot resolve domain name"]],
                ["Nikto found 0 vulnerabilities",1,proc_med," <  4m","golism8",["Cannot resolve domain name","Nikto found 0 vulnerabilities"]],
                ["Possible subdomain leak",0,proc_high," < 30m","golism9",["Cannot resolve domain name"]],
                ["AXFR record query failed:",1,proc_low," < 45s","dnsenumzt",["NS record query failed:","AXFR record query failed","no NS record for"]],
                ["Found 0 entries",1,proc_high," < 75m","fierce2",["Found 0 entries","is gimp"]],
                ["Found 0 E-Mail(s)",1,proc_low," < 30s","dmitry1",["Unable to locate Host IP addr","Found 0 E-Mail(s)"]],
                ["Found 0 possible subdomain(s)",1,proc_low," < 35s","dmitry2",["Unable to locate Host IP addr","Found 0 possible subdomain(s)"]],
                ["open",0,proc_low," < 15s","nmaptelnet",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmapftp",["Failed to resolve"]],
                ["open",0,proc_low," < 20s","nmapstux",["Failed to resolve"]],
                ["SUCCEED",0,proc_low," < 30s","webdav",["is not DAV enabled or not accessible."]],
                ["No vulnerabilities found",1,proc_low," < 15s","golism10",["Cannot resolve domain name","No vulnerabilities found"]],
                ["[+]",0,proc_med," <  2m","uniscan2",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  5m","uniscan3",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  9m","uniscan4",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  8m","uniscan5",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  9m","uniscan6",["Use of uninitialized value in unpack at"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto1",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto2",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto3",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto4",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto5",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto6",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto7",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto8",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto9",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto10",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto11",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto12",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto13",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto14","ERROR: Cannot resolve hostname , 0 item(s) reported"],
                ["#1",0,proc_high," < 30m","dnsmap_brute",["[+] 0 (sub)domains and 0 IP address(es) found"]],
                ["open",0,proc_low," < 15s","nmapmssql",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmapmysql",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmaporacle",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmapudprdp",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmaptcprdp",["Failed to resolve"]],
                ["open",0,proc_high," > 50m","nmapfulltcp",["Failed to resolve"]],
                ["open",0,proc_high," > 75m","nmapfulludp",["Failed to resolve"]],
                ["open",0,proc_low," < 30s","nmapsnmp",["Failed to resolve"]],
                ["Microsoft SQL Server Error Log",0,proc_low," < 30s","elmahxd",["unable to resolve host address","Connection timed out"]],
                ["open",0,proc_low," < 20s","nmaptcpsmb",["Failed to resolve"]],
                ["open",0,proc_low," < 20s","nmapudpsmb",["Failed to resolve"]],
                ["Host:",0,proc_med," < 5m","wapiti",["none"]],
                ["WebDAV is ENABLED",0,proc_low," < 40s","nmapwebdaviis",["Failed to resolve"]],
                ["X-XSS-Protection[1",1,proc_med," < 3m","whatweb",["Timed out","Socket error","X-XSS-Protection[1"]]



            ]

  


