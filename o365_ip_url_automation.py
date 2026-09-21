#!/bin/python
# -*- coding: utf-8 -*-
# Office 365 IP Address and URL Web Service Automation for BIG-IP
# https://docs.microsoft.com/en-us/Office365/Enterprise/office-365-ip-web-service
# Version: 1.11
# Last Modified: 16th July 2020
# Original author: Makoto Omura, F5 Networks Japan G.K.
#
# v1.05: Updated for SSL Orchestrator by Kevin Stewart, SSA, F5 Networks
# v1.06: Updated by Brett Smith, Principal Systems Engineer
# v1.06: Ability to create data groups and/or URL categories. IPv4/IPv6 data group support only.
# v1.07: Updated to properly pass "*" to tmsh command (by M.O. 9 July 2020)
# v1.08: Endpoint category filter (Optimize/Allow/Default), safer wildcard handling for URL data group, Python 2/3 compatible
# v1.09: Intune/Autopilot (MEM service area, own version tracking) and extra_urls for Autopilot endpoints missing from the feed
# v1.10: exclude_urls to drop overly broad or irrelevant patterns from the feed
# v1.11: Static Intune/Autopilot list from the consolidated Intune endpoint list (web service MEM off by default),
#        two URL categories: O365_Bypass (SSL bypass) and O365_NoAuth (SSL intercept), static lists part of version
#
# This Sample Software provided by the author is for illustrative
# purposes only which provides customers with programming information
# regarding the products. This software is supplied "AS IS" without any
# warranties and support.
#
# The author assumes no responsibility or liability for the use of the
# software, conveys no license or title under any patent, copyright, or
# mask work right to the product.
#
# The author reserves the right to make changes in the software without
# notification. The author also make no representation or warranty that
# such application will be suitable for the specified use without
# further testing or modification.

try:
    import httplib                      # Python 2 (TMOS /bin/python)
except ImportError:
    import http.client as httplib       # Python 3
import urllib
import uuid
import os
import re
import json
try:
    import commands                     # Python 2 (TMOS /bin/python)
except ImportError:
    import subprocess as commands       # Python 3 (getoutput)
import datetime
import sys
import hashlib

#-----------------------------------------------------------------------
# User Options - Configure as desired
#-----------------------------------------------------------------------

# O365 Record types to download & update
use_url = 0     # Create custom category for URL based proxy bypassing - requires APM: 0=do not use, 1=use
use_url_dg = 1  # Create data group for URL based proxy bypassing: 0=do not use, 1=use
use_ipv4 = 1    # Create data group for IPv4 based routing: 0=do not use, 1=use
use_ipv6 = 0    # Create data group for IPv6 based routing: 0=do not use, 1=use

# O365 "SeviceArea" (application) to consume
care_common = 1     # "Common": 0=do not care, 1=care
care_exchange = 1   # "Exchange": 0=do not care, 1=care
care_skype = 1      # "Skype": 0=do not care, 1=care
care_sharepoint = 1 # "SharePoint": 0=do not care, 1=care
care_yammer = 1     # "Yammer": 0=do not care, 1=care (no longer present in the Worldwide feed)
care_mem = 0        # "MEM" (Intune / Autopilot) from the web service: 0=do not care, 1=care.
                    # Default 0: Microsoft now states the web service MEM data is insufficient and to use the
                    # consolidated list on learn.microsoft.com/intune/fundamentals/endpoints (see intune_urls below).
care_mem_all_categories = 1  # 1=take every MEM endpoint set regardless of category (Autopilot needs the Default ones:
                             #   Windows Update, NTP, WNS, TPM EK certs, attestation, diagnostics). 0=apply category filter below

# O365 endpoint "category" to consume (network connectivity principles)
# Optimize = latency sensitive (Exchange Online, SharePoint, Teams media), best candidates for bypass
# Allow    = important but less sensitive
# Default  = everything else (CRL/OCSP, CDNs, broad *.microsoft.com, etc.)
care_optimize = 1   # "Optimize": 0=do not care, 1=care
care_allow = 1      # "Allow": 0=do not care, 1=care
care_default = 0    # "Default": 0=do not care, 1=care

# Tenant name used to expand mid-string wildcards, e.g. autodiscover.*.onmicrosoft.com
# -> autodiscover.<tenant>.onmicrosoft.com. Leave empty to skip those entries in the URL data group.
o365_tenant_name = ""

# Static Intune / Autopilot endpoints, added to the URL data group and URL categories.
# Sources: "Network endpoints for Microsoft Intune" consolidated list and "Windows Autopilot requirements"
# (learn.microsoft.com). Left out on purpose: Remote Help, US GCC, *.powershellgallery.com, cdn.oneget.org, aka.ms.
# Editing these lists triggers a refresh on the next run (they are part of the stored version string).
use_extra_urls = 1  # 0=do not use, 1=use
extra_urls = [
    # Autopilot deployment service and Microsoft account
    "ztd.dds.microsoft.com", "login.live.com", "account.live.com",
    # Entra ID join / device registration
    "login.microsoftonline.com", "enterpriseregistration.windows.net",
    "certauth.enterpriseregistration.windows.net", "graph.windows.net",
    "aadcdn.msauth.net", "aadcdn.msftauth.net",
    # Intune service (enrollment, check-in, Win32/IME CDNs, macOS sidecar), Defender / EPM
    "manage.microsoft.com", "*.manage.microsoft.com", "*.dm.microsoft.com", "*.events.data.microsoft.com",
    # TPM attestation (self-deploying / pre-provisioning) and firmware TPM EK certificates
    "*.microsoftaik.azure.net", "ekop.intel.com", "ekcert.spserv.microsoft.com", "ftpm.amd.com",
    # Device health attestation: MAA (Windows 11) and DHA (Windows 10)
    "intunemaape1.eus.attest.azure.net", "intunemaape2.eus2.attest.azure.net", "intunemaape3.cus.attest.azure.net",
    "intunemaape4.wus.attest.azure.net", "intunemaape5.scus.attest.azure.net", "intunemaape6.ncus.attest.azure.net",
    "intunemaape7.neu.attest.azure.net", "intunemaape8.neu.attest.azure.net", "intunemaape9.neu.attest.azure.net",
    "intunemaape10.weu.attest.azure.net", "intunemaape11.weu.attest.azure.net", "intunemaape12.weu.attest.azure.net",
    "intunemaape13.jpe.attest.azure.net", "intunemaape17.jpe.attest.azure.net", "intunemaape18.jpe.attest.azure.net",
    "intunemaape19.jpe.attest.azure.net", "has.spserv.microsoft.com",
    # Windows Update and Delivery Optimization
    "*.windowsupdate.com", "*.update.microsoft.com", "*.delivery.mp.microsoft.com", "*.dl.delivery.mp.microsoft.com",
    "dl.delivery.mp.microsoft.com", "*.do.dsp.mp.microsoft.com", "tsfe.trafficshaping.dsp.mp.microsoft.com",
    "adl.windows.com",
    # Microsoft Store API and Win32 fallback cache
    "displaycatalog.mp.microsoft.com", "purchase.md.mp.microsoft.com", "licensing.mp.microsoft.com",
    "storeedgefd.dsx.mp.microsoft.com", "cdn.storeedgefd.dsx.mp.microsoft.com",
    # Windows Push Notification Services
    "*.notify.windows.com", "*.wns.windows.com", "clientconfig.passport.net", "windowsphone.com", "*.s-microsoft.com",
    # Discovery, feature deployment, organizational messages, Office config
    "go.microsoft.com", "config.edge.skype.com", "ecs.office.com", "fd.api.orgmsg.microsoft.com",
    "ris.prod.api.personalization.ideas.microsoft.com", "config.office.com", "*.officeconfig.msocdn.com",
    # Connectivity check (NCSI, plain HTTP)
    "*.msftconnecttest.com",
    # Autopilot diagnostics upload (Intune docs: amsu*, Autopilot docs: lgmsape*)
    "amsua0101lmsas.blob.core.windows.net", "amsua0102lmsas.blob.core.windows.net",
    "amsua0201lmsas.blob.core.windows.net", "amsua0202lmsas.blob.core.windows.net",
    "amsua0401lmsas.blob.core.windows.net", "amsua0402lmsas.blob.core.windows.net",
    "amsua0501lmsas.blob.core.windows.net", "amsua0502lmsas.blob.core.windows.net",
    "amsua0601lmsas.blob.core.windows.net", "amsua0602lmsas.blob.core.windows.net",
    "amsua0701lmsas.blob.core.windows.net", "amsua0702lmsas.blob.core.windows.net",
    "amsua0801lmsas.blob.core.windows.net", "amsua0901lmsas.blob.core.windows.net",
    "amsua0902lmsas.blob.core.windows.net", "amsub0101lmsas.blob.core.windows.net",
    "amsub0102lmsas.blob.core.windows.net", "amsub0201lmsas.blob.core.windows.net",
    "amsub0202lmsas.blob.core.windows.net", "amsub0301lmsas.blob.core.windows.net",
    "amsub0302lmsas.blob.core.windows.net", "amsub0501lmsas.blob.core.windows.net",
    "amsub0502lmsas.blob.core.windows.net", "amsub0601lmsas.blob.core.windows.net",
    "amsub0701lmsas.blob.core.windows.net", "amsub0801lmsas.blob.core.windows.net",
    "amsub0901lmsas.blob.core.windows.net", "amsuc0101lmsas.blob.core.windows.net",
    "amsuc0201lmsas.blob.core.windows.net", "amsuc0301lmsas.blob.core.windows.net",
    "amsuc0501lmsas.blob.core.windows.net", "amsuc0601lmsas.blob.core.windows.net",
    "amsud0101lmsas.blob.core.windows.net", "amsuin01lmsas.blob.core.windows.net",
    "lgmsapeweu.blob.core.windows.net", "lgmsapewus2.blob.core.windows.net", "lgmsapesea.blob.core.windows.net",
    "lgmsapeaus.blob.core.windows.net", "lgmsapeind.blob.core.windows.net",
]

# Static Intune core service subnets (consolidated list), added to the IPv4 / IPv6 data groups.
use_intune_ips = 1  # 0=do not use, 1=use
intune_ips = [
    "4.145.74.224/27", "4.150.254.64/27", "4.154.145.224/27", "4.200.254.32/27", "4.207.244.0/27",
    "4.213.25.64/27", "4.213.86.128/25", "4.216.205.32/27", "4.237.143.128/25", "13.67.13.176/28",
    "13.67.15.128/27", "13.69.67.224/28", "13.69.231.128/28", "13.70.78.128/28", "13.70.79.128/27",
    "13.74.111.192/27", "13.77.53.176/28", "13.86.221.176/28", "13.89.174.240/28", "13.89.175.192/28",
    "20.37.153.0/24", "20.37.192.128/25", "20.38.81.0/24", "20.41.1.0/24", "20.42.1.0/24",
    "20.42.130.0/24", "20.42.224.128/25", "20.43.129.0/24", "20.44.19.224/27", "20.91.147.72/29",
    "20.168.189.128/27", "20.189.172.160/27", "20.189.229.0/25", "20.191.167.0/25", "20.192.159.40/29",
    "20.192.174.216/29", "20.199.207.192/28", "20.204.193.10/31", "20.204.193.12/30", "20.204.194.128/31",
    "20.208.149.192/27", "20.208.157.128/27", "20.214.131.176/29", "40.67.121.224/27", "40.70.151.32/28",
    "40.71.14.96/28", "40.74.25.0/24", "40.78.245.240/28", "40.78.247.128/27", "40.79.197.64/27",
    "40.79.197.96/28", "40.80.180.208/28", "40.80.180.224/27", "40.80.184.128/25", "40.82.248.224/28",
    "40.82.249.128/25", "40.84.70.128/25", "40.119.8.128/25", "48.218.252.128/25", "52.150.137.0/25",
    "52.162.111.96/28", "52.168.116.128/27", "52.182.141.192/27", "52.236.189.96/27", "52.240.244.160/27",
    "57.151.0.192/27", "57.153.235.0/25", "57.154.140.128/25", "57.154.195.0/25", "57.155.45.128/25",
    "68.218.134.96/27", "74.224.214.64/27", "74.242.35.0/25", "104.46.162.96/27", "104.208.197.64/27",
    "172.160.217.160/27", "172.201.237.160/27", "172.202.86.192/27", "172.205.63.0/25", "172.212.214.0/25",
    "172.215.131.0/27",
    # Azure Front Door (shared by Microsoft security services)
    "13.107.219.0/24", "13.107.227.0/24", "13.107.228.0/23", "150.171.97.0/24",
    "2620:1ec:40::/48", "2620:1ec:49::/48", "2620:1ec:4a::/47",
]

# URL categories (use_url = 1). URLs are split in two categories for the SWG per-request policy:
#   o365_category_bypass : no proxy auth, SSL bypass  (Optimize endpoint sets + ssl_bypass_urls)
#   o365_category_noauth : no proxy auth, SSL intercept (everything else, e.g. login.* for Tenant Restrictions)
o365_category_bypass = "O365_Bypass"
o365_category_noauth = "O365_NoAuth"
ssl_bypass_urls = [
    # Microsoft: SSL inspection not supported
    "manage.microsoft.com", "*.manage.microsoft.com", "*.dm.microsoft.com", "*.events.data.microsoft.com",
    "has.spserv.microsoft.com",
    "intunemaape1.eus.attest.azure.net", "intunemaape2.eus2.attest.azure.net", "intunemaape3.cus.attest.azure.net",
    "intunemaape4.wus.attest.azure.net", "intunemaape5.scus.attest.azure.net", "intunemaape6.ncus.attest.azure.net",
    "intunemaape7.neu.attest.azure.net", "intunemaape8.neu.attest.azure.net", "intunemaape9.neu.attest.azure.net",
    "intunemaape10.weu.attest.azure.net", "intunemaape11.weu.attest.azure.net", "intunemaape12.weu.attest.azure.net",
    "intunemaape13.jpe.attest.azure.net", "intunemaape17.jpe.attest.azure.net", "intunemaape18.jpe.attest.azure.net",
    "intunemaape19.jpe.attest.azure.net",
    "displaycatalog.mp.microsoft.com", "purchase.md.mp.microsoft.com", "licensing.mp.microsoft.com",
    "storeedgefd.dsx.mp.microsoft.com",
    # Microsoft: bypass recommended when the proxy does TLS inspection (Delivery Optimization)
    "*.do.dsp.mp.microsoft.com",
    # Recommended: device-to-Microsoft traffic during Autopilot (deployment service, TPM, Windows Update)
    "ztd.dds.microsoft.com", "*.microsoftaik.azure.net", "ekop.intel.com", "ekcert.spserv.microsoft.com",
    "ftpm.amd.com", "*.windowsupdate.com", "*.update.microsoft.com", "*.delivery.mp.microsoft.com",
    "*.dl.delivery.mp.microsoft.com", "dl.delivery.mp.microsoft.com", "tsfe.trafficshaping.dsp.mp.microsoft.com",
    "adl.windows.com",
]

# URL patterns from the feed to drop (exact pattern as published by Microsoft, case-insensitive).
# Applied to the URL data group and URL category. Does not affect IP data groups.
use_exclude_urls = 1  # 0=do not use, 1=use
exclude_urls = [
    "*.webpubsub.azure.com",                            # Any tenant's Azure Web PubSub (Android Remote Help only)
    "*.monitor.azure.com",                              # Any tenant's Azure Monitor endpoints
    "*.gov.teams.microsoft.us",                         # US GCC only
    "remoteassistanceweb.usgov.communication.azure.us", # US GCC only
]

# Action if O365 endpoint list is not updated
force_o365_record_refresh = 0   # 0=do not update, 1=update (for test/debug purpose)

# BIG-IP HA Configuration
device_group_name = "device-group1"     # Name of Sync-Failover Device Group.  Required for HA paired BIG-IP.
ha_config = 0                           # 0=stand alone, 1=HA paired

# Log configuration
log_level = 1   # 0=none, 1=normal, 2=verbose

# Microsoft Web Service URIs (enable only one webservice version)
uri_ms_o365_endpoints = "/endpoints/Worldwide?ClientRequestId="
#uri_ms_o365_endpoints = "/endpoints/USGovDoD?ClientRequestId="
#uri_ms_o365_endpoints = "/endpoints/USGovGCCHigh?ClientRequestId="
#uri_ms_o365_endpoints = "/endpoints/China?ClientRequestId="
#uri_ms_o365_endpoints = "/endpoints/Germany?ClientRequestId="


#-----------------------------------------------------------------------
# System Options - Modify only when necessary
#-----------------------------------------------------------------------


# BIG-IP Data Group names
urls_dg = "o365_url_dg"
ipv4_dg = "o365_ipv4_dg"
ipv6_dg = "o365_ipv6_dg"

# Work directory, file name for guid & version management
work_directory = "/var/tmp/o365"
file_name_guid = "/var/tmp/o365/guid.txt"
file_ms_o365_version = "/var/tmp/o365/o365_version.txt"
log_dest_file = "/var/log/o365_update"
dg_file_name_urls = "/var/tmp/o365/o365_urls.txt"
dg_file_name_ip4 = "/var/tmp/o365/o365_ip4.txt"
dg_file_name_ip6 = "/var/tmp/o365/o365_ip6.txt"

# Microsoft Web Service URLs
url_ms_o365_endpoints = "endpoints.office.com"
url_ms_o365_version = "endpoints.office.com"
uri_ms_o365_version = "/version?ClientRequestId="


#-----------------------------------------------------------------------
# Implementation - Please do not modify
#-----------------------------------------------------------------------
list_urls_to_bypass = []
list_urls_ssl_bypass = []
list_urls_to_bypass_fin = []
string_urls_to_bypass_fin = ""
list_ips4_to_pbr = []
list_ips6_to_pbr = []
failover_state = ""

def log(lev, msg):
    if log_level >= lev:
        log_string = "{0:%Y-%m-%d %H:%M:%S}".format(datetime.datetime.now()) + " " + msg + "\n"
        f = open(log_dest_file, "a")
        f.write(log_string)
        f.flush()
        f.close()
    return

def get_latest_version(guid, service_area):
    # Return the latest Worldwide version for the given service area ("" = O365 default areas, "MEM" = Intune)
    request_string = uri_ms_o365_version + guid
    if service_area:
        request_string += "&ServiceAreas=" + service_area
    conn = httplib.HTTPSConnection(url_ms_o365_version)
    conn.request('GET', request_string)
    res = conn.getresponse()
    if not res.status == 200:
        log(1, "VERSION request (" + (service_area or "O365") + ") to MS web service failed.  Assuming VERSIONs did not match, and proceed.")
        return ""
    log(2, "VERSION request (" + (service_area or "O365") + ") to MS web service was successful.")
    for record in json.loads(res.read()):
        if record.get("instance") == "Worldwide" and re.match('[0-9]{10}', record.get("latest", "")):
            return record["latest"]
    return ""

def update_url_category(name, urls, version):
    # Create new or clean out existing URL category - add the feed version as first entry
    result = commands.getoutput("tmsh list sys url-db url-category " + name)
    if "was not found" in result:
        commands.getoutput("tmsh create /sys url-db url-category " + name + " display-name " + name)
        log(2, "Custom URL category not found. Created new custom category: " + name)
    else:
        log(2, "Custom URL category exists. Clearing entries for new data: " + name)
    commands.getoutput("tmsh modify /sys url-db url-category " + name + " urls replace-all-with { https://" + version + "/ { type exact-match } }")

    str_urls = ""
    for url in sorted(urls):
        if "*" in url:
            log(2, name + ": glob-match entries for " + url)
            # Escaping any asterisk characters
            url_processed = re.sub('\\*', '\\\\\\*', url)
            # Both HTTPS and HTTP category lookups use "https://"; HTTP URLs match the entry without trailing slash
            str_urls += " urls add { \"https://" + url_processed + "/\" { type glob-match } } urls add { \"https://" + url_processed + "\" { type glob-match } }"
        else:
            log(2, name + ": exact-match entries for " + url)
            str_urls += " urls add { https://" + url + "/ { type exact-match } } urls add { https://" + url + " { type exact-match } }"

    if str_urls:
        result = commands.getoutput("tmsh modify /sys url-db url-category " + name + str_urls)
        log(2, "URL DB update result (" + name + "): " + result)

def normalize_dg_url(url):
    # Convert an O365 URL pattern to a suffix usable with 'class match ... ends_with'.
    # Returns None when the pattern cannot be expressed safely as a suffix.
    url = url.lower()
    if "*" not in url:
        return url
    if url.startswith("*."):
        # *.office.com -> .office.com (subdomains only, same as original behaviour)
        return url[1:]
    if url.startswith("*") and "*" not in url[1:]:
        # *cdn.onenote.net -> cdn.onenote.net (ends_with also matches xyzcdn.onenote.net)
        return url[1:]
    if url.count("*") == 1 and o365_tenant_name:
        # autodiscover.*.onmicrosoft.com -> autodiscover.<tenant>.onmicrosoft.com
        return url.replace("*", o365_tenant_name.lower())
    # Mid-string wildcard without tenant: stripping it would bypass far too much (e.g. .onmicrosoft.com)
    return None

def main():

    # -----------------------------------------------------------------------
    # Check if this BIG-IP is ACTIVE for the traffic group (= traffic_group_name)
    # -----------------------------------------------------------------------
    result = commands.getoutput("tmsh show /cm failover-status field-fmt")

    if ("status ACTIVE" in result)\
        or (ha_config == 0):
        failover_state = "active"       # For future use
        log(1, "This BIG-IP is ACTIVE. Initiating O365 update.")
    else:
        failover_state = "non-active"   # For future use
        log(1, "This BIG-IP is STANDBY. Aborting O365 update.")
        sys.exit(0)


    # -----------------------------------------------------------------------
    # GUID management
    # -----------------------------------------------------------------------
    # Create guid file if not existent
    if not os.path.isdir(work_directory):
        os.mkdir(work_directory)
        log(1, "Created work directory " + work_directory + " because it did not exist.")
    if not os.path.exists(file_name_guid):
        f = open(file_name_guid, "w")
        f.write("\n")
        f.flush()
        f.close()
        log(1, "Created GUID file " + file_name_guid + " because it did not exist.")

    # Read guid from file and validate.  Create one if not existent
    f = open(file_name_guid, "r")
    f_content = f.readline()
    f.close()
    if re.match('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', f_content):
        guid = f_content
        log(2, "Valid GUID is read from local file " + file_name_guid + ".")
    else:
        guid = str(uuid.uuid4())
        f = open(file_name_guid, "w")
        f.write(guid)
        f.flush()
        f.close()
        log(1, "Generated a new GUID, and saved it to " + file_name_guid + ".")


    # -----------------------------------------------------------------------
    # O365 endpoints list version check
    # -----------------------------------------------------------------------
    # Read version of previously received record
    if os.path.isfile(file_ms_o365_version):
        f = open(file_ms_o365_version, "r")
        f_content = f.readline()
        f.close()
        # Check if the VERSION record format is valid
        if re.match('[0-9]{10}', f_content):
            ms_o365_version_previous = f_content
            log(2, "Valid previous VERSION found in " + file_ms_o365_version + ".")
        else:
            ms_o365_version_previous = "1970010200"
            f = open(file_ms_o365_version, "w")
            f.write(ms_o365_version_previous)
            f.flush()
            f.close()
            log(1, "Valid previous VERSION was not found.  Wrote dummy value in " + file_ms_o365_version + ".")
    else:
        ms_o365_version_previous = "1970010200"
        f = open(file_ms_o365_version, "w")
        f.write(ms_o365_version_previous)
        f.flush()
        f.close()
        log(1, "Valid previous VERSION was not found.  Wrote dummy value in " + file_ms_o365_version + ".")


    # -----------------------------------------------------------------------
    # O365 endpoints list VERSION check
    # -----------------------------------------------------------------------
    ms_o365_version_latest = get_latest_version(guid, "")
    ms_version_combined = ms_o365_version_latest
    if care_mem:
        # MEM (Intune/Autopilot) is versioned separately from the O365 service areas
        ms_version_combined = ms_o365_version_latest + "-" + get_latest_version(guid, "MEM")

    # Static lists are part of the version so that editing them triggers a refresh
    static_config = repr((extra_urls if use_extra_urls else [], intune_ips if use_intune_ips else [],
                          exclude_urls if use_exclude_urls else [], ssl_bypass_urls))
    ms_version_combined += "-" + hashlib.md5(static_config.encode("utf-8")).hexdigest()[:8]

    if re.match('[0-9]{10}', ms_o365_version_latest):
        f = open(file_ms_o365_version, "w")
        f.write(ms_version_combined)
        f.flush()
        f.close()

    log(2, "Previous VERSION is " + ms_o365_version_previous)
    log(2, "Latest VERSION is " + ms_version_combined)

    if ms_version_combined == ms_o365_version_previous and force_o365_record_refresh == 0:
        log(1, "You already have the latest MS O365 URL/IP Address list: " + ms_version_combined + ". Aborting operation.")
        sys.exit(0)


    # -----------------------------------------------------------------------
    # Request O365 endpoints list & put it in dictionary
    # -----------------------------------------------------------------------
    request_string = uri_ms_o365_endpoints + guid
    if care_mem:
        # MEM is only returned when requested explicitly; listing all areas keeps the others in the response
        request_string += "&ServiceAreas=Common,Exchange,SharePoint,Skype,MEM"
    conn = httplib.HTTPSConnection(url_ms_o365_endpoints)
    conn.request('GET', request_string)
    res = conn.getresponse()

    if not res.status == 200:
        log(1, "ENDPOINTS request to MS web service failed. Aborting operation.")
        sys.exit(0)
    else:
        log(2, "ENDPOINTS request to MS web service was successful.")
        dict_o365_all = json.loads(res.read())

    # Process for each record(id) of the endpoint JSON data
    for dict_o365_record in dict_o365_all:
        service_area = str(dict_o365_record['serviceArea'])
        id = str(dict_o365_record['id'])

        if (care_common and service_area == "Common") \
            or (care_exchange and service_area == "Exchange") \
            or (care_sharepoint and service_area == "SharePoint") \
            or (care_skype and service_area == "Skype") \
            or (care_yammer and service_area == "Yammer") \
            or (care_mem and service_area == "MEM"):

            category = str(dict_o365_record.get('category', ''))
            if not ((care_optimize and category == "Optimize") \
                or (care_allow and category == "Allow") \
                or (care_default and category == "Default") \
                or (care_mem_all_categories and service_area == "MEM")):
                log(2, "Skipping endpoint set id " + id + " (" + service_area + "/" + category + "): category not selected.")
                continue

            if use_url or use_url_dg:
                # Append "urls" if existent in each record
                if ('urls' in dict_o365_record):
                    list_urls = list(dict_o365_record['urls'])
                    for url in list_urls:
                        list_urls_to_bypass.append(url)
                        if category == "Optimize":
                            list_urls_ssl_bypass.append(url)

                # Append "allowUrls" if existent in each record
                if ('allowUrls' in dict_o365_record):
                    list_allow_urls = list(dict_o365_record['allowUrls'])
                    for url in list_allow_urls:
                        list_urls_to_bypass.append(url)

                # Append "defaultUrls" if existent in each record
                if ('defaultUrls' in dict_o365_record):
                    list_default_urls = dict_o365_record['defaultUrls']
                    for url in list_default_urls:
                        list_urls_to_bypass.append(url)

            if use_ipv4 or use_ipv6:
                # Append "ips" if existent in each record
                if ('ips' in dict_o365_record):
                    list_ips = list(dict_o365_record['ips'])
                    for ip in list_ips:
                        if re.match('^.+:', ip):
                            list_ips6_to_pbr.append(ip)
                        else:
                            list_ips4_to_pbr.append(ip)

    if use_extra_urls and (use_url or use_url_dg):
        log(2, "Adding " + str(len(extra_urls)) + " extra URLs from extra_urls.")
        list_urls_to_bypass.extend(extra_urls)

    if use_url or use_url_dg:
        list_urls_ssl_bypass.extend(ssl_bypass_urls)
        list_urls_to_bypass.extend(ssl_bypass_urls)

    if use_intune_ips and (use_ipv4 or use_ipv6):
        log(2, "Adding " + str(len(intune_ips)) + " static Intune subnets from intune_ips.")
        for ip in intune_ips:
            if ":" in ip:
                list_ips6_to_pbr.append(ip)
            else:
                list_ips4_to_pbr.append(ip)

    if use_exclude_urls and (use_url or use_url_dg):
        excludes = set(u.lower() for u in exclude_urls)
        removed = sorted(set(u for u in list_urls_to_bypass if u.lower() in excludes))
        list_urls_to_bypass[:] = [u for u in list_urls_to_bypass if u.lower() not in excludes]
        log(1, "Excluded " + str(len(removed)) + " URL patterns from exclude_urls: " + ", ".join(removed))

    num_list_urls_to_bypass = len(list_urls_to_bypass)
    num_list_ips4_to_pbr = len(list_ips4_to_pbr)
    num_list_ips6_to_pbr = len(list_ips6_to_pbr)
    log(1, "Number of ENDPOINTS to import : URL:" + str(num_list_urls_to_bypass) + ", IPv4 host/net:" + str(num_list_ips4_to_pbr) + ", IPv6 host/net:" + str(num_list_ips6_to_pbr))


    # -----------------------------------------------------------------------
    # O365 endpoint URLs re-formatted to fit into custom URL category
    # -----------------------------------------------------------------------
    if use_url:
        urls_all = set(u.lower() for u in list_urls_to_bypass)
        urls_bypass = set(u.lower() for u in list_urls_ssl_bypass) & urls_all
        urls_noauth = urls_all - urls_bypass
        log(1, "URL categories: " + o365_category_bypass + "=" + str(len(urls_bypass)) + ", " + o365_category_noauth + "=" + str(len(urls_noauth)))
        update_url_category(o365_category_bypass, urls_bypass, ms_o365_version_latest)
        update_url_category(o365_category_noauth, urls_noauth, ms_o365_version_latest)

    # -----------------------------------------------------------------------
    # O365 endpoints URL asterisk removal and re-format to fit into Data Group
    # -----------------------------------------------------------------------
    if use_url_dg:
        # Process asterisk nicely.  Force lower case letter.
        for url in list_urls_to_bypass:
            url_processed = normalize_dg_url(url)
            if url_processed is None:
                log(1, "Skipping URL pattern " + url + " for data group: mid-string wildcard (set o365_tenant_name to expand it).")
                continue
            list_urls_to_bypass_fin.append(url_processed)

        # URL sort & dedupe. Generate file for External Data Group
        fout = open(dg_file_name_urls, 'w')
        for url in (list(sorted(set(list_urls_to_bypass_fin)))):
            fout.write(str(url) + " := 1,\n")
        fout.flush()
        fout.close()

        #-----------------------------------------------------------------------
        # Data Group File update
        #-----------------------------------------------------------------------
        # The object appears in WebUI: System › File Management : Data Group File List >> xxx_object
        # Name of the Data Group is given in urls_dg
        # Name of the Data Group File is urls_dg + "_object"

        result = commands.getoutput("tmsh list sys file data-group " + urls_dg + "_object")
        # Create or update Data Group File from text file (given for variable "dg_file_name_urls")
        if "was not found" in result:
            result2 = commands.getoutput("tmsh create /sys file data-group " + urls_dg + "_object type string source-path file:" + dg_file_name_urls)
            log(2, "Data Group File " + urls_dg + "_object was not found.  Created from " + dg_file_name_urls + ".")
        else:
            result2 = commands.getoutput("tmsh modify /sys file data-group " + urls_dg + "_object source-path file:" + dg_file_name_urls)
            log(2, "Data Group File " + urls_dg + "_object was found.  Updated from " + dg_file_name_urls + ".")

        #-----------------------------------------------------------------------
        # Make sure Data Group exists that corresponds to File update
        #-----------------------------------------------------------------------
        # The object appears in WebUI: Local Traffic >> iRules : Data Group List >> (External File) xxx
        # The object needs to exist, but does not have to be explicitly updated by this script

        result = commands.getoutput("tmsh list /ltm data-group external " + urls_dg)
        if "was not found" in result:
            result2 = commands.getoutput("tmsh create /ltm data-group external " + urls_dg + " external-file-name " + urls_dg + "_object")
            log(2, "Data Group " + urls_dg + " was not found.  Creating it from " + urls_dg + "_object")

    # -----------------------------------------------------------------------
    # IPv4 addresses saved into text files separately
    # -----------------------------------------------------------------------
    # Process IP dictionaries
    if use_ipv4:
        # Write IPv4 list
        fout = open(dg_file_name_ip4, 'w')
        for ip4 in (list(sorted(set(list_ips4_to_pbr)))):
            fout.write("network " + str(ip4) + ",\n")
        fout.flush()
        fout.close()

        #-----------------------------------------------------------------------
        # Data Group File update
        #-----------------------------------------------------------------------
        # The object appears in WebUI: System › File Management : Data Group File List >> xxx_object
        # Name of the Data Group is given in ipv4_dg
        # Name of the Data Group File is ipv4_dg + "_object"

        result = commands.getoutput("tmsh list sys file data-group " + ipv4_dg + "_object")
        # Create or update Data Group File from text file (given for variable "dg_file_name_ip4")
        if "was not found" in result:
            result2 = commands.getoutput("tmsh create /sys file data-group " + ipv4_dg + "_object type ip source-path file:" + dg_file_name_ip4)
            log(2, "Data Group File " + ipv4_dg + "_object was not found.  Created from " + dg_file_name_ip4 + ".")
        else:
            result2 = commands.getoutput("tmsh modify /sys file data-group " + ipv4_dg + "_object source-path file:" + dg_file_name_ip4)
            log(2, "Data Group File " + ipv4_dg + "_object was found.  Updated from " + dg_file_name_ip4 + ".")

        #-----------------------------------------------------------------------
        # Make sure Data Group exists that corresponds to File update
        #-----------------------------------------------------------------------
        # The object appears in WebUI: Local Traffic >> iRules : Data Group List >> (External File) xxx
        # The object needs to exist, but does not have to be explicitly updated by this script

        result = commands.getoutput("tmsh list /ltm data-group external " + ipv4_dg)
        if "was not found" in result:
            result2 = commands.getoutput("tmsh create /ltm data-group external " + ipv4_dg + " external-file-name " + ipv4_dg + "_object")
            log(2, "Data Group " + ipv4_dg + " was not found.  Creating it from " + ipv4_dg + "_object")

    # -----------------------------------------------------------------------
    # IPv6 addresses saved into text files separately
    # -----------------------------------------------------------------------
    # Process IP dictionaries
    if use_ipv6:
        # Write IPv6 list
        fout = open(dg_file_name_ip6, 'w')
        for ip6 in (list(sorted(set(list_ips6_to_pbr)))):
            fout.write("network " + str(ip6) + ",\n")
        fout.flush()
        fout.close()

        #-----------------------------------------------------------------------
        # Data Group File update
        #-----------------------------------------------------------------------
        # The object appears in WebUI: System › File Management : Data Group File List >> xxx_object
        # Name of the Data Group is given in ipv6_dg
        # Name of the Data Group File is ipv6_dg + "_object"

        result = commands.getoutput("tmsh list sys file data-group " + ipv6_dg + "_object")
        # Create or update Data Group File from text file (given for variable "dg_file_name_ip6")
        if "was not found" in result:
            result2 = commands.getoutput("tmsh create /sys file data-group " + ipv6_dg + "_object type ip source-path file:" + dg_file_name_ip6)
            log(2, "Data Group File " + ipv6_dg + "_object was not found.  Created from " + dg_file_name_ip6 + ".")
        else:
            result2 = commands.getoutput("tmsh modify /sys file data-group " + ipv6_dg + "_object source-path file:" + dg_file_name_ip6)
            log(2, "Data Group File " + ipv6_dg + "_object was found.  Updated from " + dg_file_name_ip6 + ".")

        #-----------------------------------------------------------------------
        # Make sure Data Group exists that corresponds to File update
        #-----------------------------------------------------------------------
        # The object appears in WebUI: Local Traffic >> iRules : Data Group List >> (External File) xxx
        # The object needs to exist, but does not have to be explicitly updated by this script

        result = commands.getoutput("tmsh list /ltm data-group external " + ipv6_dg)
        if "was not found" in result:
            result2 = commands.getoutput("tmsh create /ltm data-group external " + ipv6_dg + " external-file-name " + ipv6_dg + "_object")
            log(2, "Data Group " + ipv6_dg + " was not found.  Creating it from " + ipv6_dg + "_object")

    #-----------------------------------------------------------------------
    # Save config
    #-----------------------------------------------------------------------
    log(1, "Saving BIG-IP Configuration.")
    result = commands.getoutput("tmsh save /sys config")
    log(2, result + "\n")


    #-----------------------------------------------------------------------
    # Initiate Config Sync: Device to Group
    #-----------------------------------------------------------------------
    if ha_config == 1:
        log(1, "Initiating Config-Sync.")
        result = commands.getoutput("tmsh run cm config-sync to-group " + device_group_name)
        log(2, result + "\n")

    log(1, "Completed O365 URL/IP address update process.")


if __name__=='__main__':
    main()
