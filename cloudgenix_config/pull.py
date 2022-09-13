# -*- coding: utf-8 -*-
"""
Configuration EXPORT worker/script

**Version:** 1.7.0b3

**Author:** CloudGenix

**Copyright:** (c) 2017, 2018 CloudGenix, Inc

**License:** MIT

**Location:** <https://github.com/CloudGenix/cloudgenix_config>

#### Synopsis
Script to traverse the CloudGenix Controller for a site/list of sites, and extract configuration to a YAML file.

#### Requirements
* Active CloudGenix Account
* Python >= 2.7 or >=3.6
* Python modules:
    * CloudGenix Python SDK >= 5.0.1b1 - <https://github.com/CloudGenix/sdk-python>

#### License
MIT

#### For more info
 * Get help and additional CloudGenix Documentation at <http://support.cloudgenix.com>

"""

import yaml
import json
import re
import sys
import os
import argparse
import copy
import datetime
import logging
import errno


# CloudGenix Python SDK
try:
    import cloudgenix
    jdout = cloudgenix.jdout
    jd = cloudgenix.jd
except ImportError as e:
    cloudgenix = None
    sys.stderr.write("ERROR: 'cloudgenix' python module required. (try 'pip install cloudgenix').\n {0}\n".format(e))
    sys.exit(1)

# import module specific
try:
    from cloudgenix_config import throw_error, throw_warning, name_lookup_in_template, extract_items, build_lookup_dict, \
    check_name, nameable_interface_types, skip_interface_list, get_function_default_args
    from cloudgenix_config import __version__ as import_cloudgenix_config_version
except Exception:
    from cloudgenix_config.cloudgenix_config import throw_error, throw_warning, name_lookup_in_template, extract_items, build_lookup_dict, \
    check_name, nameable_interface_types, skip_interface_list, get_function_default_args
    from cloudgenix_config.cloudgenix_config import __version__ as import_cloudgenix_config_version

# Check config file, in cwd.
sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # will get caught below.
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None


# python 2 and 3 handling
if sys.version_info < (3,):
    text_type = unicode
    binary_type = str
    python_version = 2
else:
    text_type = str
    binary_type = bytes
    python_version = 3

__author__ = "CloudGenix Developer Support <developers@cloudgenix.com>"
__email__ = "developers@cloudgenix.com"
__copyright__ = "Copyright (c) 2017, 2018 CloudGenix, Inc"
__license__ = """
    MIT License

    Copyright (c) 2017, 2018 CloudGenix, Inc

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
"""


# Globals
CONFIG = {}
SITES = {}
ELEMENTS = {}
REPORT_ID = False
STRIP_VERSIONS = False
FORCE_PARENTS = False
SITES_STR = "sites"
ELEMENTS_STR = "elements"
WANINTERFACES_STR = "waninterfaces"
LANNETWORKS_STR = "lannetworks"
INTERFACES_STR = "interfaces"
STATIC_STR = "static"
AGENT_STR = "agent"
TRAPS_STR = "traps"
NTP_STR = "ntp"
SYSLOG_STR = "syslog"
TOOLKIT_STR = "toolkit"
SITE_SECURITYZONES_STR = "site_security_zones"
ELEMENT_SECURITYZONES_STR = "element_security_zones"
ELEMENT_EXTENSIONS_STR = "element_extensions"
SITE_EXTENSIONS_STR = "site_extensions"
DHCP_SERVERS_STR = "dhcpservers"
BGP_GLOBAL_CONFIG_STR = "global_config"
BGP_PEERS_CONFIG_STR = "peers"
ROUTEMAP_CONFIG_STR = "route_maps"
ASPATHACL_CONFIG_STR = "as_path_access_lists"
PREFIXLISTS_CONFIG_STR = "prefix_lists"
IPCOMMUNITYLISTS_CONFIG_STR = "ip_community_lists"
HUBCLUSTER_CONFIG_STR = "hubclusters"
SPOKECLUSTER_CONFIG_STR = "spokeclusters"
NATLOCALPREFIX_STR = "site_nat_localprefixes"
DNS_SERVICES_STR = "dnsservices"
APPLICATION_PROBE_STR = "application_probe"
IPFIX_STR = "ipfix"
SITE_IPFIXLOCALPREFIXES_STR = "site_ipfix_localprefixes"
MULTICASTGLOBALCONFIGS_STR = "multicastglobalconfigs"
MULTICASTRPS_STR = "multicastrps"
CELLULAR_MODULES_SIM_SECURITY_STR = "cellular_modules_sim_security"
ELEMENT_CELLULAR_MODULES_STR = "element_cellular_modules"
ELEMENT_CELLULAR_MODULES_FIRMWARE_STR = "element_cellular_modules_firmware"
# MULTICASTPEERGROUPS_STR = "multicastpeergroups"

# Global Config Cache holders
sites_cache = []
elements_cache = []
machines_cache = []
policysets_cache = []
security_policysets_cache = []
ngfw_security_policysetstack_cache = []
syslogserverprofiles_cache = []
securityzones_cache = []
network_policysetstack_cache = []
priority_policysetstack_cache = []
waninterfacelabels_cache = []
wannetworks_cache = []
wanoverlays_cache = []
servicebindingmaps_cache = []
serviceendpoints_cache = []
ipsecprofiles_cache = []
networkcontexts_cache = []
appdefs_cache = []
natglobalprefixes_cache = []
natlocalprefixes_cache = []
natpolicypools_cache = []
natpolicysetstacks_cache = []
natzones_cache = []
dnsserviceprofiles_cache = []
dnsserviceroles_cache = []
ipfixprofile_cache = []
ipfixcollectorcontext_cache = []
ipfixfiltercontext_cache = []
ipfixtemplate_cache = []
ipfixlocalprefix_cache = []
ipfixglobalprefix_cache = []
apnprofiles_cache = []
multicastpeergroups_cache = []

id_name_cache = {}
sites_n2id = {}
wannetworks_id2type = {}
dup_name_dict_sites = {}

# Handle cloudblade calls
FROM_CLOUDBLADE = 0
# Fix for CGCBL-565
SDK_VERSION_REQUIRED = '5.6.1b2'  # Version when these fields were introduced in yml as meta attr
CONFIG_VERSION_REQUIRED = '1.6.0b2'
# Define constructor globally for now.
sdk = None
jd = cloudgenix.jd

# Set logging to use function name
logger = logging.getLogger(__name__)

idreg = re.compile('^[0-9]+$')


# replace NULL exported YAML values with blanks. Semantically the same, but easier to read.
def represent_none(self, _):
    return self.represent_scalar('tag:yaml.org,2002:null', '')


yaml.add_representer(type(None), represent_none, Dumper=yaml.SafeDumper)


def dump_version():
    """
    Dump version info to string and exit.
    :return: Multiline String.
    """
    # Got request for versions. Dump and exit
    try:
        python_ver = sys.version
    except NameError:
        python_ver = "Unknown"
    try:
        cloudgenix_config_ver = import_cloudgenix_config_version
    except NameError:
        cloudgenix_config_ver = "Unknown"
    try:
        cloudgenix_ver = cloudgenix.version
    except NameError:
        cloudgenix_ver = "Unknown"
    try:
        json_ver = json.__version__
    except NameError:
        json_ver = "Unknown"
    try:
        yaml_ver = yaml.__version__
    except NameError:
        yaml_ver = "Unknown"
    try:
        logging_ver = logging.__version__
    except NameError:
        logging_ver = "Unknown"

    output = ""
    output += "**PROGRAM VERSIONS**, "
    output += "Python version: {0}, ".format(python_ver)
    output += "'cloudgenix_config' version: {0}, ".format(cloudgenix_config_ver)
    output += "'cloudgenix' version: {0}, ".format(cloudgenix_ver)
    output += "'json' version: {0}, ".format(json_ver)
    output += "'yaml' version: {0}, ".format(yaml_ver)
    output += "'logging' version: {0}, ".format(logging_ver)
    return output


def update_global_cache():
    """
    Update Cache of Global objects (not Site or Element Specific)
    :return: No Return, mutates global objects in-place.
    """
    global sites_cache
    global elements_cache
    global machines_cache
    global policysets_cache
    global security_policysets_cache
    global ngfw_security_policysetstack_cache
    global syslogserverprofiles_cache
    global securityzones_cache
    global network_policysetstack_cache
    global priority_policysetstack_cache
    global waninterfacelabels_cache
    global wannetworks_cache
    global wanoverlays_cache
    global servicebindingmaps_cache
    global serviceendpoints_cache
    global ipsecprofiles_cache
    global networkcontexts_cache
    global appdefs_cache
    global natglobalprefixes_cache
    global natlocalprefixes_cache
    global natpolicypools_cache
    global natpolicysetstacks_cache
    global natzones_cache
    global dnsserviceprofiles_cache
    global dnsserviceroles_cache
    global ipfixprofile_cache
    global ipfixcollectorcontext_cache
    global ipfixfiltercontext_cache
    global ipfixtemplate_cache
    global ipfixlocalprefix_cache
    global ipfixglobalprefix_cache
    global apnprofiles_cache
    global multicastpeergroups_cache

    global id_name_cache
    global wannetworks_id2type
    global sites_n2id

    # sites
    sites_resp = sdk.get.sites()
    sites_cache, _ = extract_items(sites_resp, 'sites')

    # elements
    elements_resp = sdk.get.elements()
    elements_cache, _ = extract_items(elements_resp, 'elements')

    # machines
    machines_resp = sdk.get.machines()
    machines_cache, _ = extract_items(machines_resp, 'machines')

    # policysets
    policysets_resp = sdk.get.policysets()
    policysets_cache, _ = extract_items(policysets_resp, 'policysets')

    # security_policysets
    security_policysets_resp = sdk.get.securitypolicysets()
    security_policysets_cache, _ = extract_items(security_policysets_resp, 'security_policysets')

    # ngfw_security_policysetstack
    ngfw_security_policysetstack_resp = sdk.get.ngfwsecuritypolicysetstacks()
    ngfw_security_policysetstack_cache, _ = extract_items(ngfw_security_policysetstack_resp, 'ngfw_securitypolicysetstack')

    # syslogserverprofiles
    syslogserverprofiles_resp = sdk.get.syslogserverprofiles()
    syslogserverprofiles_cache, _ = extract_items(syslogserverprofiles_resp, 'syslogserverprofiles')

    # secuirityzones
    securityzones_resp = sdk.get.securityzones()
    securityzones_cache, _ = extract_items(securityzones_resp, 'secuirityzones')

    # network_policysetstack
    network_policysetstack_resp = sdk.get.networkpolicysetstacks()
    network_policysetstack_cache, _ = extract_items(network_policysetstack_resp, 'network_policysetstack')

    # prioroty_policysetstack
    prioroty_policysetstack_resp = sdk.get.prioritypolicysetstacks()
    prioroty_policysetstack_cache, _ = extract_items(prioroty_policysetstack_resp, 'prioroty_policysetstack')

    # waninterfacelabels
    waninterfacelabels_resp = sdk.get.waninterfacelabels()
    waninterfacelabels_cache, _ = extract_items(waninterfacelabels_resp, 'waninterfacelabels')

    # wannetworks
    wannetworks_resp = sdk.get.wannetworks()
    wannetworks_cache, _ = extract_items(wannetworks_resp, 'wannetworks')

    # wanoverlays
    wanoverlays_resp = sdk.get.wanoverlays()
    wanoverlays_cache, _ = extract_items(wanoverlays_resp, 'wanoverlays')

    # servicebindingmaps
    servicebindingmaps_resp = sdk.get.servicebindingmaps()
    servicebindingmaps_cache, _ = extract_items(servicebindingmaps_resp, 'servicebindingmaps')

    # serviceendpoints
    serviceendpoints_resp = sdk.get.serviceendpoints()
    serviceendpoints_cache, _ = extract_items(serviceendpoints_resp, 'serviceendpoints')

    # ipsecprofiles
    ipsecprofiles_resp = sdk.get.ipsecprofiles()
    ipsecprofiles_cache, _ = extract_items(ipsecprofiles_resp, 'ipsecprofiles')

    # networkcontexts
    networkcontexts_resp = sdk.get.networkcontexts()
    networkcontexts_cache, _ = extract_items(networkcontexts_resp, 'networkcontexts')

    # appdef
    appdefs_resp = sdk.get.appdefs()
    appdefs_cache, _ = extract_items(appdefs_resp, 'appdefs')

    # NAT Global Prefixes
    natglobalprefixes_resp = sdk.get.natglobalprefixes()
    natglobalprefixes_cache, _ = extract_items(natglobalprefixes_resp, 'natglobalprefixes')

    # NAT Local Prefixes
    natlocalprefixes_resp = sdk.get.natlocalprefixes()
    natlocalprefixes_cache, _ = extract_items(natlocalprefixes_resp, 'natlocalprefixes')

    # NAT Policy Pools
    natpolicypools_resp = sdk.get.natpolicypools()
    natpolicypools_cache, _ = extract_items(natpolicypools_resp, 'natpolicypools')

    # NAT natpolicysetstacks
    natpolicysetstacks_resp = sdk.get.natpolicysetstacks()
    natpolicysetstacks_cache, _ = extract_items(natpolicysetstacks_resp, 'natpolicysetstacks')

    # NAT zones
    natzones_resp = sdk.get.natzones()
    natzones_cache, _ = extract_items(natzones_resp, 'natzones')

    # dnsservice profiles
    dnsserviceprofiles_resp = sdk.get.dnsserviceprofiles()
    dnsserviceprofiles_cache, _ = extract_items(dnsserviceprofiles_resp, 'dnsserviceprofiles')

    # dnsservice roles
    dnsserviceroles_resp = sdk.get.dnsserviceroles()
    dnsserviceroles_cache, _ = extract_items(dnsserviceroles_resp, 'dnsserviceroles')

    # ipfixprofile
    ipfixprofile_resp = sdk.get.ipfixprofiles()
    ipfixprofile_cache, _ = extract_items(ipfixprofile_resp, 'ipfixprofiles')

    # ipfixcollectorcontext
    ipfixcollectorcontext_resp = sdk.get.ipfixcollectorcontexts()
    ipfixcollectorcontext_cache, _ = extract_items(ipfixcollectorcontext_resp, 'ipfixcollectorcontexts')

    # ipfixfiltercontext
    ipfixfiltercontext_resp = sdk.get.ipfixfiltercontexts()
    ipfixfiltercontext_cache, _ = extract_items(ipfixfiltercontext_resp, 'ipfixfiltercontexts')

    # ipfixtemplate
    ipfixtemplate_resp = sdk.get.ipfixtemplates()
    ipfixtemplate_cache, _ = extract_items(ipfixtemplate_resp, 'ipfixtemplates')

    # ipfixlocalprefix
    ipfixlocalprefix_resp = sdk.get.tenant_ipfixlocalprefixes()
    ipfixlocalprefix_cache, _ = extract_items(ipfixlocalprefix_resp, 'tenant_ipfixlocalprefixes')

    # ipfixglobalprefix
    ipfixglobalprefix_resp = sdk.get.ipfixglobalprefixes()
    ipfixglobalprefix_cache, _ = extract_items(ipfixglobalprefix_resp, 'ipfixglobalprefixes')

    # apnprofiles
    apnprofiles_resp = sdk.get.apnprofiles()
    apnprofiles_cache, _ = extract_items(apnprofiles_resp, 'apnprofiles')

    # multicastpeergroups
    multicastpeergroups_resp = sdk.get.multicastpeergroups()
    multicastpeergroups_cache, _ = extract_items(multicastpeergroups_resp, 'multicastpeergroups')

    # sites name
    id_name_cache.update(build_lookup_dict(sites_cache, key_val='id', value_val='name'))

    # sites name to ID
    sites_n2id.update(build_lookup_dict(sites_cache))

    # element name
    id_name_cache.update(build_lookup_dict(elements_cache, key_val='id', value_val='name'))

    # policysets name
    id_name_cache.update(build_lookup_dict(policysets_cache, key_val='id', value_val='name'))

    # security_policysets name
    id_name_cache.update(build_lookup_dict(security_policysets_cache, key_val='id', value_val='name'))

    # ngfw_securitypolicysetstack name
    id_name_cache.update(build_lookup_dict(ngfw_security_policysetstack_cache, key_val='id', value_val='name'))

    # syslogserverprofiles name
    id_name_cache.update(build_lookup_dict(syslogserverprofiles_cache, key_val='id', value_val='name'))

    # securityzones name
    id_name_cache.update(build_lookup_dict(securityzones_cache, key_val='id', value_val='name'))

    # network_policysetstack name
    id_name_cache.update(build_lookup_dict(network_policysetstack_cache, key_val='id', value_val='name'))

    # prioroty_policysetstack name
    id_name_cache.update(build_lookup_dict(prioroty_policysetstack_cache, key_val='id', value_val='name'))

    # waninterfacelabels name
    id_name_cache.update(build_lookup_dict(waninterfacelabels_cache, key_val='id', value_val='name'))

    # wannetworks name
    id_name_cache.update(build_lookup_dict(wannetworks_cache, key_val='id', value_val='name'))

    # wanoverlays name
    id_name_cache.update(build_lookup_dict(wanoverlays_cache, key_val='id', value_val='name'))

    # servicebindingmaps name
    id_name_cache.update(build_lookup_dict(servicebindingmaps_cache, key_val='id', value_val='name'))

    # serviceendpoints name
    id_name_cache.update(build_lookup_dict(serviceendpoints_cache, key_val='id', value_val='name'))

    # ipsecprofiles name
    id_name_cache.update(build_lookup_dict(ipsecprofiles_cache, key_val='id', value_val='name'))

    # networkcontexts name
    id_name_cache.update(build_lookup_dict(networkcontexts_cache, key_val='id', value_val='name'))

    # appdefs name
    id_name_cache.update(build_lookup_dict(appdefs_cache, key_val='id', value_val='display_name'))

    # NAT Global Prefixes name
    id_name_cache.update(build_lookup_dict(natglobalprefixes_cache, key_val='id', value_val='name'))

    # NAT Local Prefixes name
    id_name_cache.update(build_lookup_dict(natlocalprefixes_cache, key_val='id', value_val='name'))

    # NAT Policy Pools name
    id_name_cache.update(build_lookup_dict(natpolicypools_cache, key_val='id', value_val='name'))

    # NAT natpolicysetstacks name
    id_name_cache.update(build_lookup_dict(natpolicysetstacks_cache, key_val='id', value_val='name'))

    # NAT zones name
    id_name_cache.update(build_lookup_dict(natzones_cache, key_val='id', value_val='name'))

    # DNS services name
    id_name_cache.update(build_lookup_dict(dnsserviceprofiles_cache, key_val='id', value_val='name'))

    id_name_cache.update(build_lookup_dict(dnsserviceroles_cache, key_val='id', value_val='name'))

    # ipfixprofile name
    id_name_cache.update(build_lookup_dict(ipfixprofile_cache, key_val='id', value_val='name'))

    # ipfixcollectorcontext name
    id_name_cache.update(build_lookup_dict(ipfixcollectorcontext_cache, key_val='id', value_val='name'))

    # ipfixfiltercontext name
    id_name_cache.update(build_lookup_dict(ipfixfiltercontext_cache, key_val='id', value_val='name'))

    # ipfixtemplate name
    id_name_cache.update(build_lookup_dict(ipfixtemplate_cache, key_val='id', value_val='name'))

    # ipfixlocalprefix name
    id_name_cache.update(build_lookup_dict(ipfixlocalprefix_cache, key_val='id', value_val='name'))

    # ipfixglobalprefix name
    id_name_cache.update(build_lookup_dict(ipfixglobalprefix_cache, key_val='id', value_val='name'))

    # apnprofiles name
    id_name_cache.update(build_lookup_dict(apnprofiles_cache, key_val='id', value_val='name'))

    # multicastpeergroups name
    id_name_cache.update(build_lookup_dict(multicastpeergroups_cache, key_val='id', value_val='name'))

    # WAN Networks ID to Type cache - will be used to disambiguate "Public" vs "Private" WAN Networks that have
    # the same name at the SWI level.
    wannetworks_id2type = build_lookup_dict(wannetworks_cache, key_val='id', value_val='type')

    return


def add_version_to_object(sdk_func, input_string):
    """
    Adds API version as version key to string
    :param sdk_func: CloudGenix sdk function
    :param input_string: Config section
    :return: input_string + ' ' + API version.
    """
    args = get_function_default_args(sdk_func)
    # extract API version
    api_version = args.get('api_version')
    # if invalid API version, set to default value
    if not api_version:
        api_version = "UNDEFINED"
    return text_type(input_string) + ' ' + text_type(api_version)


def build_version_strings():
    """
    Populate global version strings with Current SDK versions.
    :return: No return, mutates globals in place.
    """
    global SITES_STR
    global ELEMENTS_STR
    global WANINTERFACES_STR
    global LANNETWORKS_STR
    global INTERFACES_STR
    global STATIC_STR
    global AGENT_STR
    global TRAPS_STR
    global NTP_STR
    global SYSLOG_STR
    global TOOLKIT_STR
    global SITE_SECURITYZONES_STR
    global ELEMENT_SECURITYZONES_STR
    global ELEMENT_EXTENSIONS_STR
    global SITE_EXTENSIONS_STR
    global DHCP_SERVERS_STR
    global BGP_GLOBAL_CONFIG_STR
    global BGP_PEERS_CONFIG_STR
    global ROUTEMAP_CONFIG_STR
    global ASPATHACL_CONFIG_STR
    global PREFIXLISTS_CONFIG_STR
    global IPCOMMUNITYLISTS_CONFIG_STR
    global HUBCLUSTER_CONFIG_STR
    global SPOKECLUSTER_CONFIG_STR
    global NATLOCALPREFIX_STR
    global DNS_SERVICES_STR
    global APPLICATION_PROBE_STR
    global IPFIX_STR
    global SITE_IPFIXLOCALPREFIXES_STR
    global MULTICASTGLOBALCONFIGS_STR
    global MULTICASTRPS_STR
    global CELLULAR_MODULES_SIM_SECURITY_STR
    global ELEMENT_CELLULAR_MODULES_STR
    global ELEMENT_CELLULAR_MODULES_FIRMWARE_STR

    if not STRIP_VERSIONS:
        # Config container strings
        SITES_STR = add_version_to_object(sdk.get.sites, "sites")
        ELEMENTS_STR = add_version_to_object(sdk.get.elements, "elements")
        WANINTERFACES_STR = add_version_to_object(sdk.get.waninterfaces, "waninterfaces")
        LANNETWORKS_STR = add_version_to_object(sdk.get.lannetworks, "lannetworks")
        INTERFACES_STR = add_version_to_object(sdk.get.interfaces, "interfaces")
        STATIC_STR = add_version_to_object(sdk.get.staticroutes, "static")
        AGENT_STR = add_version_to_object(sdk.get.snmpagents, "agent")
        TRAPS_STR = add_version_to_object(sdk.get.snmptraps, "traps")
        NTP_STR = add_version_to_object(sdk.get.ntp, "ntp")
        SYSLOG_STR = add_version_to_object(sdk.get.syslogservers, "syslog")
        TOOLKIT_STR = add_version_to_object(sdk.get.elementaccessconfigs, "toolkit")
        SITE_SECURITYZONES_STR = add_version_to_object(sdk.get.sitesecurityzones, "site_security_zones")
        ELEMENT_SECURITYZONES_STR = add_version_to_object(sdk.get.elementsecurityzones,
                                                          "element_security_zones")
        ELEMENT_EXTENSIONS_STR = add_version_to_object(sdk.get.element_extensions, "element_extensions")
        SITE_EXTENSIONS_STR = add_version_to_object(sdk.get.site_extensions, "site_extensions")
        DHCP_SERVERS_STR = add_version_to_object(sdk.get.dhcpservers, "dhcpservers")
        BGP_GLOBAL_CONFIG_STR = add_version_to_object(sdk.get.bgpconfigs, "global_config")
        BGP_PEERS_CONFIG_STR = add_version_to_object(sdk.get.bgppeers, "peers")
        ROUTEMAP_CONFIG_STR = add_version_to_object(sdk.get.routing_routemaps, "route_maps")
        ASPATHACL_CONFIG_STR = add_version_to_object(sdk.get.routing_aspathaccesslists, "as_path_access_lists")
        PREFIXLISTS_CONFIG_STR = add_version_to_object(sdk.get.routing_prefixlists, "prefix_lists")
        IPCOMMUNITYLISTS_CONFIG_STR = add_version_to_object(sdk.get.routing_ipcommunitylists,
                                                            "ip_community_lists")
        HUBCLUSTER_CONFIG_STR = add_version_to_object(sdk.get.routing_prefixlists, "hubclusters")
        SPOKECLUSTER_CONFIG_STR = add_version_to_object(sdk.get.spokeclusters, "spokeclusters")
        NATLOCALPREFIX_STR = add_version_to_object(sdk.get.site_natlocalprefixes, "site_nat_localprefixes")
        DNS_SERVICES_STR = add_version_to_object(sdk.get.dnsservices, "dnsservices")
        APPLICATION_PROBE_STR = add_version_to_object(sdk.get.application_probe, "application_probe")
        IPFIX_STR = add_version_to_object(sdk.get.ipfix, "ipfix")
        SITE_IPFIXLOCALPREFIXES_STR = add_version_to_object(sdk.get.site_ipfixlocalprefixes, "site_ipfix_localprefixes")
        MULTICASTGLOBALCONFIGS_STR = add_version_to_object(sdk.get.multicastglobalconfigs, "multicastglobalconfigs")
        MULTICASTRPS_STR = add_version_to_object(sdk.get.multicastrps, "multicastrps")
        CELLULAR_MODULES_SIM_SECURITY_STR = add_version_to_object(sdk.get.cellular_modules_sim_security, "cellular_modules_sim_security")
        ELEMENT_CELLULAR_MODULES_STR = add_version_to_object(sdk.get.element_cellular_modules, "element_cellular_modules")
        ELEMENT_FIRMWARE_CELLULAR_MODULES_STR = add_version_to_object(sdk.get.element_cellular_modules_firmware, "element_cellular_modules_firmware")

def strip_meta_attributes(obj, leave_name=False, report_id=None):
    """
    Strip meta attributes and names
    :param obj: CloudGenix config item dict.
    :param leave_name: Bool, Leave 'name' field in dict
    :param report_id: Bool or None, Leave 'id' field in dict. If None, uses global REPORT_ID
    :return:
    """

    # report_id from global unless specified.
    if report_id is None:
        report_id = REPORT_ID

    # Python 3 needs implicit list to allow del of items in iterated .keys() list
    for key in list(obj.keys()):
        if key[0] == "_":
            del obj[key]
        # name will be in reference for most items.
        elif key == 'name' and not leave_name:
            del obj[key]
        # implicit IDs should be deleted as well unless specifically asked for.
        elif key == 'id' and not report_id:
            del obj[key]


def delete_if_empty(variable_dict, key):
    """
    Check for "Empty" var (in this case, {} [] "" etc, but not 0 or False), and delete.
    :param variable_dict: Dict (1 level)
    :param key: Key Name
    :return: No return, mutates variable_dict in place.
    """
    if key in variable_dict:
        val = variable_dict[key]
        if not val and not isinstance(val, bool) and val != 0:
            variable_dict.pop(key)
    return


def _pull_config_for_single_site(site_name_id):
    """
    Function to pull configuration from CloudGenix controller, and save as YAML file.
    Needs cloudgenix_config globals set (sdk, cache, etc). Rework eventually to allow running
    directly.
    :param site_name_id: Site name or ID.
    :return: No return, mutates CONFIG var in place.
    """
    global id_name_cache
    global dup_name_dict_sites

    # Opportunistic replace Name w/ID.
    site_id = sites_n2id.get(site_name_id, site_name_id)

    site = None

    for site_entry in SITES:
        if site_entry['id'] == site_id:
            site = site_entry
            break

    if not site:
        throw_warning("Site name/id \"{0}\" not found.".format(site_name_id))
        return

    # Get site name from object for error messages. This may differ from what is put into yml
    # if this site name is a duplicate with another site.
    error_site_name = site['name']

    if "multicast_peer_group_id" in site:
        site["multicast_peer_group_id"] = id_name_cache.get(site["multicast_peer_group_id"])
    # Get WAN interfaces
    dup_name_dict = {}
    site[WANINTERFACES_STR] = {}
    response = sdk.get.waninterfaces(site['id'])
    if not response.cgx_status:
        throw_error("WAN interfaces get failed: ", response)
    waninterfaces = response.cgx_content['items']
    # update id_name_cache
    id_name_cache.update(build_lookup_dict(waninterfaces, key_val='id', value_val='name'))
    for waninterface in waninterfaces:
        waninterface_template = copy.deepcopy(waninterface)
        name_lookup_in_template(waninterface_template, 'label_id', id_name_cache)
        name_lookup_in_template(waninterface_template, 'network_id', id_name_cache)

        # if name is not set, set to "Circuit to <WAN Network Name>"
        ui_normalized_name = waninterface.get('name')
        if not ui_normalized_name:
            wannetwork_name = waninterface_template.get('network_id')
            ui_normalized_name = "Circuit to " + text_type(wannetwork_name)
            throw_warning('Site WAN Interface is missing a name. Please correct this in UI. '
                          'Setting to "{0}" in YAML file, but this may cause issues if configuration is re-applied '
                          'to site.'.format(ui_normalized_name), waninterface)

        # create a new construct, 'network_type'. This will be used for disambiguation when
        # doing name->ID translation when reapplying this configuration, and will be removed before apply.
        network_id = waninterface.get('network_id')
        if network_id:
            # look up type by network id
            wannetwork_type = wannetworks_id2type.get(network_id)
            if wannetwork_type:
                # was able to get the type string (publicwan, privatewan), use it in template.
                waninterface_template['network_type'] = wannetwork_type

        strip_meta_attributes(waninterface_template)
        # check name for duplicates
        checked_waninterface_name = check_name(ui_normalized_name, dup_name_dict, 'Waninterface',
                                               error_site_txt="{0}({1})".format(error_site_name,
                                                                                site_id))
        # update id name cache in case name changed.
        id_name_cache[waninterface['id']] = checked_waninterface_name
        site[WANINTERFACES_STR][checked_waninterface_name] = waninterface_template
    delete_if_empty(site, WANINTERFACES_STR)

    # Get LAN Networks
    dup_name_dict = {}
    site[LANNETWORKS_STR] = {}
    response = sdk.get.lannetworks(site['id'])
    if not response.cgx_status:
        throw_error("LAN networks get failed: ", response)
    lannetworks = response.cgx_content['items']
    # update id_name_cache
    id_name_cache.update(build_lookup_dict(lannetworks, key_val='id', value_val='name'))
    for lannetwork in lannetworks:
        lannetwork_template = copy.deepcopy(lannetwork)
        name_lookup_in_template(lannetwork_template, 'network_context_id', id_name_cache)
        name_lookup_in_template(lannetwork_template, 'security_policy_set', id_name_cache)
        strip_meta_attributes(lannetwork_template)
        # check name for duplicates
        checked_lannetwork_name = check_name(lannetwork['name'], dup_name_dict, 'Laninterface',
                                             error_site_txt="{0}({1})".format(error_site_name,
                                                                              site_id))
        # update id name cache in case name changed.
        id_name_cache[lannetwork['id']] = checked_lannetwork_name
        site[LANNETWORKS_STR][checked_lannetwork_name] = lannetwork_template
    delete_if_empty(site, LANNETWORKS_STR)

    # Get Hub Clusters
    dup_name_dict = {}
    site[HUBCLUSTER_CONFIG_STR] = {}
    response = sdk.get.hubclusters(site['id'])
    if not response.cgx_status:
        throw_error("Hub Clusters get failed: ", response)
    hubclusters = response.cgx_content['items']
    # update id_name_cache
    id_name_cache.update(build_lookup_dict(hubclusters, key_val='id', value_val='name'))
    for hubcluster in hubclusters:
        hubcluster_template = copy.deepcopy(hubcluster)
        name_lookup_in_template(hubcluster_template, 'network_context_id', id_name_cache)
        name_lookup_in_template(hubcluster_template, 'security_policy_set', id_name_cache)
        strip_meta_attributes(hubcluster_template)
        # check name for duplicates
        checked_hubcluster_name = check_name(hubcluster['name'], dup_name_dict, 'Hubcluster',
                                             error_site_txt="{0}({1})".format(error_site_name,
                                                                              site_id))
        # update id name cache in case name changed.
        id_name_cache[hubcluster['id']] = checked_hubcluster_name
        site[HUBCLUSTER_CONFIG_STR][checked_hubcluster_name] = hubcluster_template
    delete_if_empty(site, HUBCLUSTER_CONFIG_STR)

    # Get Spoke Clusters
    dup_name_dict = {}
    site[SPOKECLUSTER_CONFIG_STR] = {}
    response = sdk.get.spokeclusters(site['id'])
    if not response.cgx_status:
        throw_error("Spoke Clusters get failed: ", response)
    spokeclusters = response.cgx_content['items']
    # update id_name_cache
    id_name_cache.update(build_lookup_dict(spokeclusters, key_val='id', value_val='name'))
    for spokecluster in spokeclusters:
        spokecluster_template = copy.deepcopy(spokecluster)
        strip_meta_attributes(spokecluster_template)
        # check name for duplicates
        checked_spokecluster_name = check_name(spokecluster['name'], dup_name_dict, 'Spokecluster',
                                               error_site_txt="{0}({1})".format(error_site_name,
                                                                                site_id))
        # update id name cache in case name changed.
        id_name_cache[spokecluster['id']] = checked_spokecluster_name
        site[SPOKECLUSTER_CONFIG_STR][checked_spokecluster_name] = spokecluster_template
    delete_if_empty(site, SPOKECLUSTER_CONFIG_STR)

    # Get DHCP Servers
    site[DHCP_SERVERS_STR] = []
    response = sdk.get.dhcpservers(site['id'])
    if not response.cgx_status:
        throw_error("DHCP Servers get failed: ", response)
    dhcpservers = response.cgx_content['items']

    for dhcpserver in dhcpservers:
        dhcpserver_template = copy.deepcopy(dhcpserver)
        name_lookup_in_template(dhcpserver_template, 'network_context_id', id_name_cache)
        strip_meta_attributes(dhcpserver_template)
        # no names, don't need duplicate check
        site[DHCP_SERVERS_STR].append(dhcpserver_template)
    delete_if_empty(site, DHCP_SERVERS_STR)

    # Get Site Extensions
    site[SITE_EXTENSIONS_STR] = {}
    response = sdk.get.site_extensions(site['id'])
    if not response.cgx_status:
        throw_error("Site Extensions get failed: ", response)
    site_extensions = response.cgx_content['items']

    for site_extension in site_extensions:
        site_extension_template = copy.deepcopy(site_extension)
        # replace flat name
        name_lookup_in_template(site_extension_template, 'entity_id', id_name_cache)
        strip_meta_attributes(site_extension_template)
        # check for duplicate names
        checked_site_extension_name = check_name(site_extension['name'], dup_name_dict, 'Site Extension',
                                                 error_site_txt="{0}({1})".format(error_site_name,
                                                                                  site_id))
        # update id name cache in case name changed.
        id_name_cache[site_extension['id']] = checked_site_extension_name
        site[SITE_EXTENSIONS_STR][checked_site_extension_name] = site_extension_template
    delete_if_empty(site, SITE_EXTENSIONS_STR)

    # Get Site Security Zones
    site[SITE_SECURITYZONES_STR] = []
    response = sdk.get.sitesecurityzones(site['id'])
    if not response.cgx_status:
        throw_error("Site Security Zones get failed: ", response)
    site_securityzones = response.cgx_content['items']

    for site_securityzone in site_securityzones:
        site_securityzone_template = copy.deepcopy(site_securityzone)
        # replace flat name
        name_lookup_in_template(site_securityzone_template, 'zone_id', id_name_cache)
        # replace complex names
        ssz_networks = site_securityzone.get('networks', None)
        if ssz_networks and isinstance(ssz_networks, list):
            ssz_networks_template = []
            for ssz_network in ssz_networks:
                ssz_network_template = copy.deepcopy(ssz_network)
                name_lookup_in_template(ssz_network_template, 'network_id', id_name_cache)
                ssz_networks_template.append(ssz_network_template)
            site_securityzone_template['networks'] = ssz_networks_template

        strip_meta_attributes(site_securityzone_template)

        site[SITE_SECURITYZONES_STR].append(site_securityzone_template)
    delete_if_empty(site, SITE_SECURITYZONES_STR)

    # Get Site NAT Localprefixes
    site[NATLOCALPREFIX_STR] = []
    response = sdk.get.site_natlocalprefixes(site['id'])
    if not response.cgx_status:
        throw_error("Site NAT Local Prefixes get failed: ", response)
    # TODO remove this MESSY HACK to work around CGB-15068.
    if response.cgx_content == {}:
        # Welcome to the land of CGB-15068. Fix in progress.
        response.cgx_content = {
            "_etag": 1,  # Hopefully this should work
            "_content_length": "0",
            "_schema": 0,
            "_created_on_utc": 15791094199340006,
            "_updated_on_utc": 0,
            "_status_code": "200",
            "_request_id": "1579109419923000400002492011547730241671",
            "count": 0,
            "items": []
        }
    # END MESSY HACK for CGB-15068

    site_natlocalprefixes = response.cgx_content['items']

    for site_natlocalprefix in site_natlocalprefixes:
        site_natlocalprefix_template = copy.deepcopy(site_natlocalprefix)
        # replace flat name
        name_lookup_in_template(site_natlocalprefix_template, 'prefix_id', id_name_cache)
        strip_meta_attributes(site_natlocalprefix_template)

        site[NATLOCALPREFIX_STR].append(site_natlocalprefix_template)
    delete_if_empty(site, NATLOCALPREFIX_STR)

    # Get Site ipfixlocalprefixes
    site[SITE_IPFIXLOCALPREFIXES_STR] = []
    response = sdk.get.site_ipfixlocalprefixes(site['id'])
    if not response.cgx_status:
        throw_error("Site IPFIX localprefixes get failed: ", response)
    site_ipfixlocalprefixes = response.cgx_content['items']

    for site_ipfix_localprefix in site_ipfixlocalprefixes:
        site_ipfix_localprefix_template = copy.deepcopy(site_ipfix_localprefix)
        # replace flat name
        name_lookup_in_template(site_ipfix_localprefix_template, 'prefix_id', id_name_cache)

        strip_meta_attributes(site_ipfix_localprefix_template)
        site[SITE_IPFIXLOCALPREFIXES_STR].append(site_ipfix_localprefix_template)

    delete_if_empty(site, SITE_IPFIXLOCALPREFIXES_STR)

    # Get Elements
    site[ELEMENTS_STR] = {}
    dup_name_dict_elements = {}
    for element in ELEMENTS:
        if element['site_id'] != site['id']:
            continue

        # Get cellular_modules
        element[ELEMENT_CELLULAR_MODULES_STR] = {}
        element[CELLULAR_MODULES_SIM_SECURITY_STR] = {}
        cellular_modules_resp = sdk.get.element_cellular_modules(element['id'])
        if not cellular_modules_resp.cgx_status:
            throw_error("Cellular Modules get failed: ", response)

        cellular_modules_all = cellular_modules_resp.cgx_content['items']
        id_name_cache.update(build_lookup_dict(cellular_modules_all, key_val='id', value_val='name'))
        for module in cellular_modules_all:
            cellular_modules_template = copy.deepcopy(module)
            cellular_module_name = cellular_modules_template.get('name')

            # Get cellular_modules_sim_security
            cellular_modules_sim_security_resp = sdk.get.cellular_modules_sim_security(element['id'], module['id'])
            if not cellular_modules_sim_security_resp.cgx_status:
                throw_error("Cellular Modules SIM Security get failed: ", response)

            cellular_modules_sim_security_all = cellular_modules_sim_security_resp.cgx_content['items']

            id_name_cache.update(build_lookup_dict(cellular_modules_sim_security_all, key_val='id', value_val='name'))
            for sim_security in cellular_modules_sim_security_all:
                cellular_modules_sim_security_template = copy.deepcopy(sim_security)
                cellular_modules_sim_security_name = cellular_modules_sim_security_template.get('name')
                strip_meta_attributes(cellular_modules_sim_security_template)
                # names used, but config doesn't index by name for this value currently.
                element[CELLULAR_MODULES_SIM_SECURITY_STR][cellular_modules_sim_security_name] =\
                    cellular_modules_sim_security_template
            delete_if_empty(element, CELLULAR_MODULES_SIM_SECURITY_STR)
            strip_meta_attributes(cellular_modules_template)
            # names used, but config doesn't index by name for this value currently.
            element[ELEMENT_CELLULAR_MODULES_STR][cellular_module_name] = cellular_modules_template
        delete_if_empty(element, ELEMENT_CELLULAR_MODULES_STR)

        # Get interfaces
        element[INTERFACES_STR] = {}
        dup_name_dict = {}
        response = sdk.get.interfaces(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Element interfaces get failed: ", response)
        interfaces = response.cgx_content['items']
        # update id_name_cache
        id_name_cache.update(build_lookup_dict(interfaces, key_val='id', value_val='name'))

        # Create interface type lookup dict
        if_id2type = build_lookup_dict(interfaces, key_val='id', value_val='type')

        # create a parent list
        parent_id_list = []
        bp_parent_id_list = []
        if_name_dict = {}
        for interface in interfaces:
            if interface.get('name') in if_name_dict:
                if_name_dict[interface.get('name')] += 1
            else:
                if_name_dict[interface.get('name')] = 1
            parent_id = interface.get('parent')
            if_type = interface.get('type')
            if parent_id is not None and if_type in ['subinterface', 'pppoe', 'port']:
                # add to parent list if it is not a service link, as service link if configs can be modified.
                # print("INTERFACE {0} is PARENT: {1}".format(parent_id, jdout(interface)))
                parent_id_list.append(parent_id)
            # Add 'parent_type' field if parent interface type is in ['subinterface', 'pppoe', 'service_link']
            # And if its bypasspair as it will cause conflict with port type
            bps = ''
            if parent_id is not None and if_type in ['subinterface', 'pppoe', 'service_link']:
                if if_id2type[parent_id] == 'bypasspair':
                    bps += '_' + id_name_cache.get(parent_id)
                    interface['parent_type'] = 'bypasspair' + bps

            bypasspair_config = interface.get('bypass_pair')
            if bypasspair_config is not None and isinstance(bypasspair_config, dict):
                # jd(bypasspair_config)
                wan_id = bypasspair_config.get('wan')
                lan_id = bypasspair_config.get('lan')
                if wan_id is not None and if_id2type.get(wan_id) in ['port']:
                    # add to parent list
                    # print("Adding WAN {0} to parent_id_list".format(wan_id))
                    parent_id_list.append(wan_id)
                    bp_parent_id_list.append(wan_id)
                if lan_id is not None and if_id2type.get(lan_id) in ['port']:
                    # add to parent list
                    # print("Adding LAN {0} to parent_id_list".format(lan_id))
                    parent_id_list.append(lan_id)
                    bp_parent_id_list.append(lan_id)

        for interface in interfaces:
            interface_id = interface.get('id')
            if_type = interface.get('type')
            if not FORCE_PARENTS and interface_id in parent_id_list:
                # interface is a parent, skip
                # Pull interface config for bypasspair and virtual interface as it can have subif/pppoe/servicelink configs
                # And its mandatory that parent gets created first
                if element.get('model_name') == 'ion 9000':  # Pull only bypasspair config for 9K if there are duplicate names in port
                    if if_name_dict[interface.get('name')] > 1:
                        if if_type != 'bypasspair':
                            continue
                    elif interface_id in bp_parent_id_list:
                        continue
                    elif if_type not in ('virtual_interface', 'bypasspair', 'port'):
                        continue
                elif interface_id in bp_parent_id_list:
                    continue
                elif if_type not in ('virtual_interface', 'bypasspair', 'port'):
                    continue
            elif FORCE_PARENTS:
                if element.get('model_name') == 'ion 9000':
                    if if_name_dict[interface.get('name')] > 1:
                        if if_type != 'bypasspair':
                            continue
            elif element.get('model_name') == 'ion 9000':
                if if_name_dict[interface.get('name')] > 1:
                    if if_type != 'bypasspair':
                        continue
            if not FORCE_PARENTS and interface.get('name') in skip_interface_list:
                # Unconfigurable interface, skip.
                continue
            # Update ids to names for complex objects in interfaces first
            interface_template = copy.deepcopy(interface)
            swi_list = interface.get('site_wan_interface_ids', None)
            # TODO: Due to CGB-8874, SWIs may get incorrectly propagated to loopbacks. As a workaround, don't
            # Process loopback SWIs (not valid for < 5.1.x).
            # Remove the loopback check below when defect above fixed.
            if swi_list and isinstance(swi_list, list) and if_type not in ['loopback']:
                swi_template = []
                for swi_id in swi_list:
                    swi_template.append(id_name_cache.get(swi_id, swi_id))
                interface_template['site_wan_interface_ids'] = swi_template
            # 2nd part of CGB-8874 workaround.
            elif if_type in ['loopback']:
                interface_template['site_wan_interface_ids'] = None

            att_ln_list = interface.get('attached_lan_networks', None)
            if att_ln_list and isinstance(att_ln_list, list):
                att_ln_template = []
                for ln in interface['attached_lan_networks']:
                    att_ln_template.append({
                        "lan_network_id": id_name_cache.get(ln['lan_network_id'], ln['lan_network_id']),
                        "vlan_id": ln['vlan_id']
                    })
                interface_template['attached_lan_networks'] = att_ln_template

            bypass_pair_dict = interface.get('bypass_pair', None)
            if bypass_pair_dict and isinstance(bypass_pair_dict, dict):
                bypasspair_template = copy.deepcopy(bypass_pair_dict)

                # replace names
                name_lookup_in_template(bypasspair_template, 'wan', id_name_cache)
                name_lookup_in_template(bypasspair_template, 'lan', id_name_cache)

                interface_template['bypass_pair'] = bypasspair_template

            servicelink_dict = interface.get('service_link_config')
            if servicelink_dict and isinstance(servicelink_dict, dict):
                servicelink_template = copy.deepcopy(servicelink_dict)

                # update nested dict
                ipsec_dict = servicelink_dict.get('ipsec_config')
                if ipsec_dict and isinstance(ipsec_dict, dict):
                    # clone dict to modify
                    ipsec_template = copy.deepcopy(ipsec_dict)

                    name_lookup_in_template(ipsec_template, 'ipsec_profile_id', id_name_cache)

                    # update nested template
                    servicelink_template['ipsec_config'] = ipsec_template

                # replace flat names in dict
                name_lookup_in_template(servicelink_template, 'service_endpoint_id', id_name_cache)

                interface_template['service_link_config'] = servicelink_template

            dhcp_relay_dict = interface.get('dhcp_relay', None)
            if dhcp_relay_dict and isinstance(dhcp_relay_dict, dict):
                dhcp_relay_template = copy.deepcopy(dhcp_relay_dict)

                # replace names
                name_lookup_in_template(dhcp_relay_template, 'source_interface', id_name_cache)

                interface_template['dhcp_relay'] = dhcp_relay_template

            nat_pools_list = interface.get('nat_pools', None)
            if nat_pools_list and isinstance(nat_pools_list, list):
                nat_pools_list_template = []
                for nat_pools_dict in nat_pools_list:

                    nat_pools_template = copy.deepcopy(nat_pools_dict)

                    # replace names
                    name_lookup_in_template(nat_pools_template, 'nat_pool_id', id_name_cache)

                    # update list with dict template
                    nat_pools_list_template.append(nat_pools_template)

                # assign list of dict templates back to object.
                interface_template['nat_pools'] = nat_pools_list_template

            # replace flat names in interface itself
            name_lookup_in_template(interface_template, 'parent', id_name_cache)
            name_lookup_in_template(interface_template, 'nat_zone_id', id_name_cache)
            name_lookup_in_template(interface_template, 'network_context_id', id_name_cache)
            # replace ipfix fields
            name_lookup_in_template(interface_template, 'ipfixcollectorcontext_id', id_name_cache)
            name_lookup_in_template(interface_template, 'ipfixfiltercontext_id', id_name_cache)

            bound_ifaces = interface.get('bound_interfaces', [])
            if bound_ifaces:
                bound_iface_template = []
                for bound_iface in bound_ifaces:
                    bound_iface_template.append(id_name_cache.get(bound_iface))
                interface_template['bound_interfaces'] = bound_iface_template

            cellular_config = interface.get('cellular_config', {})
            if cellular_config:
                apnprofile_id = cellular_config.get('apnprofile_id')
                parent_module_id = cellular_config.get('parent_module_id')
            else:
                apnprofile_id = None
                parent_module_id = None
            if apnprofile_id:
                interface_template['cellular_config']['apnprofile_id'] = id_name_cache.get(apnprofile_id, apnprofile_id)
            if parent_module_id:
                interface_template['cellular_config']['parent_module_id'] = id_name_cache.get(parent_module_id, parent_module_id)
            # strip metadata/names
            strip_meta_attributes(interface_template)
            # ok. Check for duplicates if it is a namable interface. If a dup is found, rename.
            interface_type = interface_template.get('type', "Unknown Interface")
            if interface_type in nameable_interface_types:
                checked_interface_name = check_name(interface['name'], dup_name_dict, interface_type,
                                                    error_site_txt="{0}({1})".format(error_site_name,
                                                                                     site_id))
                # update id name cache in case name changed.
                id_name_cache[interface['id']] = checked_interface_name
                element[INTERFACES_STR][checked_interface_name] = interface_template
            else:
                element[INTERFACES_STR][interface['name']] = interface_template

        element['routing'] = {}

        # Get static routes
        element['routing'][STATIC_STR] = {}
        response = sdk.get.staticroutes(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Static routes get failed: ", response)
        staticroutes = response.cgx_content['items']
        for staticroute in staticroutes:
            staticroute_template = copy.deepcopy(staticroute)
            nexthops = staticroute.get('nexthops')
            if nexthops and isinstance(nexthops, list):
                nexthops_template, bps = [], ''
                for nexthop in nexthops:
                    nexthop_template = copy.deepcopy(nexthop)
                    nexthop_interface_id = nexthop_template.get('nexthop_interface_id')
                    # Add 'parent_type' field if model is 9k and interface is bypasspair
                    if if_id2type.get(nexthop_interface_id) == 'bypasspair':
                        bps += '_' + id_name_cache.get(nexthop_interface_id)
                        nexthop_template['parent_type'] = 'bypasspair' + bps
                    # replace flat names in dict
                    name_lookup_in_template(nexthop_template, 'nexthop_interface_id', id_name_cache)
                    # add to list
                    nexthops_template.append(nexthop_template)
                staticroute_template['nexthops'] = nexthops_template

            # check for duplicate names
            checked_staticroute_name = check_name(staticroute_template.get('name'), dup_name_dict, 'Static Route',
                                               error_site_txt="{0}({1})".format(error_site_name,
                                                                                site_id))
            # update id name cache in case name changed.
            id_name_cache[staticroute_template.get('id')] = checked_staticroute_name
            strip_meta_attributes(staticroute_template)
            element['routing'][STATIC_STR][checked_staticroute_name] = staticroute_template

        delete_if_empty(element, STATIC_STR)

        # Get BGP configuration
        element['routing']['bgp'] = {}

        # grab all queries now so we can update id_name_cache.
        bgp_global_response = sdk.get.bgpconfigs(site['id'], element['id'])
        bgp_global_cache, _ = extract_items(bgp_global_response, 'bgp_global_config')

        bgp_peers_response = sdk.get.bgppeers(site['id'], element['id'])
        bgp_peers_cache, _ = extract_items(bgp_peers_response, 'bgp_peer_config')

        routemaps_response = sdk.get.routing_routemaps(site['id'], element['id'])
        routemaps_cache, _ = extract_items(routemaps_response, 'routemap_config')

        aspath_access_lists_response = sdk.get.routing_aspathaccesslists(site['id'], element['id'])
        aspath_access_lists_cache, _ = extract_items(aspath_access_lists_response, 'aspath_access_list_config')

        routing_prefixlists_response = sdk.get.routing_prefixlists(site['id'], element['id'])
        routing_prefixlists_cache, _ = extract_items(routing_prefixlists_response, 'routing_prefixlists_config')

        ip_community_lists_response = sdk.get.routing_ipcommunitylists(site['id'], element['id'])
        ip_community_lists_cache, _ = extract_items(ip_community_lists_response, 'ip_community_lists_config')

        # add responses to id_name_cache.
        id_name_cache.update(build_lookup_dict(bgp_peers_cache, key_val='id', value_val='name'))
        id_name_cache.update(build_lookup_dict(routemaps_cache, key_val='id', value_val='name'))
        id_name_cache.update(build_lookup_dict(aspath_access_lists_cache, key_val='id', value_val='name'))
        id_name_cache.update(build_lookup_dict(routing_prefixlists_cache, key_val='id', value_val='name'))
        id_name_cache.update(build_lookup_dict(ip_community_lists_cache, key_val='id', value_val='name'))

        # get global BGP config
        # only 1 BGP Config (Global config) per element.
        bgpglobal = bgp_global_cache[0]
        bgpglobal_template = copy.deepcopy(bgpglobal)
        strip_meta_attributes(bgpglobal_template)
        # no name field for this item
        element['routing']['bgp'][BGP_GLOBAL_CONFIG_STR] = bgpglobal_template
        delete_if_empty(element['routing']['bgp'], BGP_GLOBAL_CONFIG_STR)

        # get BGP peer config
        element['routing']['bgp'][BGP_PEERS_CONFIG_STR] = {}
        dup_name_dict = {}
        for bgp_peer in bgp_peers_cache:
            bgp_peer_template = copy.deepcopy(bgp_peer)
            # replace flat name
            name_lookup_in_template(bgp_peer_template, 'route_map_in_id', id_name_cache)
            name_lookup_in_template(bgp_peer_template, 'route_map_out_id', id_name_cache)
            strip_meta_attributes(bgp_peer_template)
            # check for duplicate names
            checked_bgp_peer_name = check_name(bgp_peer['name'], dup_name_dict, 'BGP Peer',
                                               error_site_txt="{0}({1})".format(error_site_name,
                                                                                site_id))
            # update id name cache in case name changed.
            id_name_cache[bgp_peer['id']] = checked_bgp_peer_name
            element['routing']['bgp'][BGP_PEERS_CONFIG_STR][checked_bgp_peer_name] = bgp_peer_template
        delete_if_empty(element['routing']['bgp'], BGP_PEERS_CONFIG_STR)

        # get Route Maps.
        element['routing'][ROUTEMAP_CONFIG_STR] = {}
        dup_name_dict = {}
        for routemap in routemaps_cache:
            routemap_template = copy.deepcopy(routemap)

            # replace complex routemap objects.
            route_map_entries_list = routemap.get('route_map_entries')
            if route_map_entries_list and isinstance(route_map_entries_list, list):

                route_map_entries_template = []
                for entry in routemap['route_map_entries']:
                    entry_template = copy.deepcopy(entry)

                    match = entry.get('match')
                    if match and isinstance(match, dict):
                        match_template = copy.deepcopy(match)
                        # replace ID with names
                        name_lookup_in_template(match_template, 'as_path_id', id_name_cache)
                        name_lookup_in_template(match_template, 'community_list_id', id_name_cache)
                        name_lookup_in_template(match_template, 'ip_next_hop_id', id_name_cache)
                        name_lookup_in_template(match_template, 'ip_prefix_list_id', id_name_cache)
                        entry_template['match'] = match_template

                    set_key = entry.get('set')
                    if set_key and isinstance(set_key, dict):
                        set_template = copy.deepcopy(set_key)
                        # replace ID with names
                        name_lookup_in_template(set_template, 'ip_next_hop_id', id_name_cache)
                        entry_template['set'] = set_template

                    # Append to template
                    route_map_entries_template.append(entry_template)

                # replace original route map entries with template
                routemap_template['route_map_entries'] = route_map_entries_template

            # replace flat names
            # name_lookup_in_template(routemap_template, 'route_map_in_id', id_name_cache)
            strip_meta_attributes(routemap_template)
            # check for duplicate names
            checked_routemap_name = check_name(routemap['name'], dup_name_dict, 'Route Map',
                                               error_site_txt="{0}({1})".format(error_site_name,
                                                                                site_id))
            # update id name cache in case name changed.
            id_name_cache[routemap['id']] = checked_routemap_name
            element['routing'][ROUTEMAP_CONFIG_STR][checked_routemap_name] = routemap_template
        delete_if_empty(element['routing'], ROUTEMAP_CONFIG_STR)

        # get AS-PATH Access Lists.
        element['routing'][ASPATHACL_CONFIG_STR] = {}
        dup_name_dict = {}
        for aspath_access_list in aspath_access_lists_cache:
            aspath_access_list_template = copy.deepcopy(aspath_access_list)
            # replace flat name
            # name_lookup_in_template(aspath_access_list_template, 'route_map_in_id', id_name_cache)
            strip_meta_attributes(aspath_access_list_template)
            # check for duplicate names
            checked_aspath_access_list_name = check_name(aspath_access_list['name'], dup_name_dict,
                                                         'AS-PATH Access List',
                                                         error_site_txt="{0}({1})".format(error_site_name,
                                                                                          site_id))
            # update id name cache in case name changed.
            id_name_cache[aspath_access_list['id']] = checked_aspath_access_list_name
            element['routing'][ASPATHACL_CONFIG_STR][checked_aspath_access_list_name] = aspath_access_list_template
        delete_if_empty(element['routing'], ASPATHACL_CONFIG_STR)

        # get Routing Prefix Lists.
        element['routing'][PREFIXLISTS_CONFIG_STR] = {}
        dup_name_dict = {}
        for routing_prefixlist in routing_prefixlists_cache:
            routing_prefixlist_template = copy.deepcopy(routing_prefixlist)
            # replace flat name
            # name_lookup_in_template(routing_prefixlist_template, 'route_map_in_id', id_name_cache)
            strip_meta_attributes(routing_prefixlist_template)
            # check for duplicate names
            checked_routing_prefixlist_name = check_name(routing_prefixlist['name'], dup_name_dict, 'Prefix List',
                                                         error_site_txt="{0}({1})".format(error_site_name,
                                                                                          site_id))
            # update id name cache in case name changed.
            id_name_cache[routing_prefixlist['id']] = checked_routing_prefixlist_name
            element['routing'][PREFIXLISTS_CONFIG_STR][checked_routing_prefixlist_name] = routing_prefixlist_template
        delete_if_empty(element['routing'], PREFIXLISTS_CONFIG_STR)

        # get IP Community lists.
        element['routing'][IPCOMMUNITYLISTS_CONFIG_STR] = {}
        dup_name_dict = {}
        for ip_community_list in ip_community_lists_cache:
            ip_community_list_template = copy.deepcopy(ip_community_list)
            # replace flat name
            # name_lookup_in_template(ip_community_list_template, 'route_map_in_id', id_name_cache)
            strip_meta_attributes(ip_community_list_template)
            # check for duplicate names
            checked_ip_community_list_name = check_name(ip_community_list['name'], dup_name_dict, 'IP-Community List',
                                                        error_site_txt="{0}({1})".format(error_site_name,
                                                                                         site_id))
            # update id name cache in case name changed.
            id_name_cache[ip_community_list['id']] = checked_ip_community_list_name
            element['routing'][IPCOMMUNITYLISTS_CONFIG_STR][checked_ip_community_list_name] = ip_community_list_template
        delete_if_empty(element['routing'], IPCOMMUNITYLISTS_CONFIG_STR)

        # Check for completely empty routing:
        delete_if_empty(element, 'routing')

        # Get multicastglobalconfigs
        element[MULTICASTGLOBALCONFIGS_STR] = []
        response = sdk.get.multicastglobalconfigs(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Multicast Global Configs get failed: ", response)
        multicastglobalconfigs = response.cgx_content['items']
        for multicastglobalconfig in multicastglobalconfigs:
            multicastglobalconfig_template = copy.deepcopy(multicastglobalconfig)
            strip_meta_attributes(multicastglobalconfig_template, leave_name=True)
            # names used, but config doesn't index by name for this value currently.
            element[MULTICASTGLOBALCONFIGS_STR].append(multicastglobalconfig_template)
        delete_if_empty(element, MULTICASTGLOBALCONFIGS_STR)

        # Get multicastrps
        element[MULTICASTRPS_STR] = []
        response = sdk.get.multicastrps(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Multicast Rendezvous Point get failed: ", response)
        multicastrps = response.cgx_content['items']
        for multicastrp in multicastrps:
            multicastrp_template = copy.deepcopy(multicastrp)
            strip_meta_attributes(multicastrp_template, leave_name=True)
            # names used, but config doesn't index by name for this value currently.
            element[MULTICASTRPS_STR].append(multicastrp_template)
        delete_if_empty(element, MULTICASTRPS_STR)

        # Get syslog
        element[SYSLOG_STR] = []
        response = sdk.get.syslogservers(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Syslog servers get failed: ", response)
        syslogservers = response.cgx_content['items']
        bps = ''
        for syslogserver in syslogservers:
            syslogserver_template = copy.deepcopy(syslogserver)
            syslog_source_interface_id = syslogserver_template.get('source_interface')
            # Add 'parent_type' field if model is 9k and interface is bypasspair
            if if_id2type.get(syslog_source_interface_id) == 'bypasspair':
                bps += '_' + id_name_cache.get(syslog_source_interface_id)
                syslogserver_template['parent_type'] = 'bypasspair' + bps
            # replace flat name
            name_lookup_in_template(syslogserver_template, 'source_interface', id_name_cache)
            name_lookup_in_template(syslogserver_template, 'syslog_profile_id', id_name_cache)
            # Fix for CGCBL-516
            if syslogserver_template.get('syslog_profile_id'):
                syslogserver_template['server_port'] = None
            strip_meta_attributes(syslogserver_template, leave_name=True)
            # names used, but config doesn't index by name for this value currently.
            element[SYSLOG_STR].append(syslogserver_template)
        delete_if_empty(element, SYSLOG_STR)

        # Get NTP configs
        element[NTP_STR] = []
        response = sdk.get.ntp(element['id'])
        if not response.cgx_status:
            throw_error("NTP config get failed: ", response)
        ntps = response.cgx_content['items']
        for ntp in ntps:
            ntp_template = copy.deepcopy(ntp)
            strip_meta_attributes(ntp_template, leave_name=True)
            if ntp.get('source_interface_ids'):
                source_ids, bps = [], ''
                for iface in ntp.get('source_interface_ids', []):
                    # Add 'parent_type' field if model is 9k and interface is bypasspair
                    if if_id2type.get(iface) == 'bypasspair':
                        bps += '_' + id_name_cache.get(iface, iface)
                        ntp_template['parent_type'] = if_id2type[iface]
                    source_ids.append(id_name_cache.get(iface, iface))
                if bps:
                    ntp_template['parent_type'] = 'bypasspair' + bps
                if source_ids:
                    ntp_template['source_interface_ids'] = source_ids
            # names used, but config doesn't index by name for this value currently.
            element[NTP_STR].append(ntp_template)
        delete_if_empty(element, NTP_STR)

        # Get element_extension configs
        element[ELEMENT_EXTENSIONS_STR] = {}
        dup_name_dict = {}
        response = sdk.get.element_extensions(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Element Extension config get failed: ", response)
        element_extensions = response.cgx_content['items']
        bps = ''
        for element_extension in element_extensions:
            element_extension_template = copy.deepcopy(element_extension)
            element_extension_entity_id = element_extension_template.get('entity_id')
            # Add 'parent_type' field if model is 9k and interface is bypasspair
            if if_id2type.get(element_extension_entity_id) == 'bypasspair':
                bps += '_' + id_name_cache.get(element_extension_entity_id)
                element_extension_template['parent_type'] = 'bypasspair' + bps
            # replace flat name
            name_lookup_in_template(element_extension_template, 'entity_id', id_name_cache)
            strip_meta_attributes(element_extension_template)
            # check for duplicate names
            checked_element_extension_name = check_name(element_extension['name'], dup_name_dict, 'Element Extension',
                                                        error_site_txt="{0}({1})".format(error_site_name,
                                                                                         site_id))
            # update id name cache in case name changed.
            id_name_cache[element_extension['id']] = checked_element_extension_name
            element[ELEMENT_EXTENSIONS_STR][checked_element_extension_name] = element_extension_template
        delete_if_empty(element, ELEMENT_EXTENSIONS_STR)

        # Get Site Security Zones
        element[ELEMENT_SECURITYZONES_STR] = []
        response = sdk.get.elementsecurityzones(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Element Security Zones get failed: ", response)
        element_securityzones = response.cgx_content['items']

        for element_securityzone in element_securityzones:
            element_securityzone_template = copy.deepcopy(element_securityzone)
            # replace flat name
            name_lookup_in_template(element_securityzone_template, 'zone_id', id_name_cache)
            # replace complex names
            esz_lannetwork_ids = element_securityzone.get('lannetwork_ids', None)
            if esz_lannetwork_ids and isinstance(esz_lannetwork_ids, list):
                esz_lannetwork_ids_template = []
                for esz_lannetwork_id in esz_lannetwork_ids:
                    esz_lannetwork_ids_template.append(id_name_cache.get(esz_lannetwork_id, esz_lannetwork_id))
                element_securityzone_template['lannetwork_ids'] = esz_lannetwork_ids_template

            esz_interface_ids = element_securityzone.get('interface_ids', None)
            if esz_interface_ids and isinstance(esz_interface_ids, list):
                esz_interface_ids_template, bps = [], ''
                for esz_interface_id in esz_interface_ids:
                    # Add 'parent_type' field if model is 9k and interface is bypasspair
                    if if_id2type.get(esz_interface_id) == 'bypasspair':
                        bps += '_' + id_name_cache.get(esz_interface_id)
                        element_securityzone_template['parent_type'] = if_id2type[esz_interface_id]
                    esz_interface_ids_template.append(id_name_cache.get(esz_interface_id, esz_interface_id))
                if bps:
                    element_securityzone_template['parent_type'] = 'bypasspair' + bps
                element_securityzone_template['interface_ids'] = esz_interface_ids_template

            esz_waninterface_ids = element_securityzone.get('waninterface_ids', None)
            if esz_waninterface_ids and isinstance(esz_waninterface_ids, list):
                esz_waninterface_ids_template = []
                for esz_waninterface_id in esz_waninterface_ids:
                    esz_waninterface_ids_template.append(id_name_cache.get(esz_waninterface_id, esz_waninterface_id))
                element_securityzone_template['waninterface_ids'] = esz_waninterface_ids_template

            esz_wanoverlay_ids = element_securityzone.get('wanoverlay_ids', None)
            if esz_wanoverlay_ids and isinstance(esz_wanoverlay_ids, list):
                esz_wanoverlay_ids_template = []
                for esz_wanoverlay_id in esz_wanoverlay_ids:
                    esz_wanoverlay_ids_template.append(id_name_cache.get(esz_wanoverlay_id, esz_wanoverlay_id))
                element_securityzone_template['wanoverlay_ids'] = esz_wanoverlay_ids_template

            strip_meta_attributes(element_securityzone_template)

            element[ELEMENT_SECURITYZONES_STR].append(element_securityzone_template)
        delete_if_empty(site, ELEMENT_SECURITYZONES_STR)

        # start SNMP section
        element['snmp'] = {}

        # Get SNMP Traps
        element['snmp'][TRAPS_STR] = []
        response = sdk.get.snmptraps(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("SNMP traps get failed: ", response)
        snmptraps = response.cgx_content['items']
        bps = ''
        for snmptrap in snmptraps:
            snmptrap_template = copy.deepcopy(snmptrap)
            snmptrap_source_interface_id = snmptrap_template.get('source_interface')
            # Add 'parent_type' field if model is 9k and interface is bypasspair
            if if_id2type.get(snmptrap_source_interface_id) == 'bypasspair':
                bps += '_' + id_name_cache.get(snmptrap_source_interface_id)
                snmptrap_template['parent_type'] = 'bypasspair' + bps
            # replace flat name
            name_lookup_in_template(snmptrap_template, 'source_interface', id_name_cache)
            strip_meta_attributes(snmptrap_template)
            # no name field for this item
            element['snmp'][TRAPS_STR].append(snmptrap_template)
        delete_if_empty(element['snmp'], TRAPS_STR)

        # Get SNMP Agent
        element['snmp'][AGENT_STR] = []
        response = sdk.get.snmpagents(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("SNMP agents get failed: ", response)
        snmpagents = response.cgx_content['items']
        for snmpagent in snmpagents:
            snmpagent_template = copy.deepcopy(snmpagent)
            strip_meta_attributes(snmpagent_template)
            # no name field for this item
            element['snmp'][AGENT_STR].append(snmpagent_template)
        delete_if_empty(element['snmp'], AGENT_STR)

        # ensure the snmp config is not completely empty
        delete_if_empty(element, 'snmp')

        # Get DNS configs
        element[DNS_SERVICES_STR] = {}
        response = sdk.get.dnsservices(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("DNS services get failed: ", response)

        dnsservices = response.cgx_content['items']
        id_name_cache.update(build_lookup_dict(dnsservices, key_val='id', value_val='name'))
        for service in dnsservices:
            dnsservices_template = copy.deepcopy(service)
            name_lookup_in_template(dnsservices_template, 'dnsservice_profile_id', id_name_cache)
            if dnsservices_template.get('dnsservicerole_bindings', ''):
                for role in dnsservices_template.get('dnsservicerole_bindings'):
                    name_lookup_in_template(role, 'dnsservicerole_id', id_name_cache)
                    if role.get('interfaces', ''):
                        bps = ''
                        for iface in role.get('interfaces'):
                            iface_interface_id = iface.get('interface_id')
                            # Add 'parent_type' field if model is 9k and interface is bypasspair
                            if if_id2type.get(iface_interface_id) == 'bypasspair':
                                bps += '_' + id_name_cache.get(iface_interface_id)
                                iface['parent_type'] = 'bypasspair' + bps
                            name_lookup_in_template(iface, 'interface_id', id_name_cache)
            if dnsservices_template.get('domains_to_interfaces', ''):
                bps = ''
                for dom_iface in dnsservices_template.get('domains_to_interfaces'):
                    dom_iface_interface_id = dom_iface.get('interface_id')
                    if if_id2type.get(dom_iface_interface_id) == 'bypasspair':
                        bps += '_' + id_name_cache.get(dom_iface_interface_id)
                        dom_iface['parent_type'] = 'bypasspair' + bps
                    name_lookup_in_template(dom_iface, 'interface_id', id_name_cache)
            name_lookup_in_template(dnsservices_template, 'element_id', id_name_cache)
            strip_meta_attributes(dnsservices_template, leave_name=True)
            # names used, but config doesn't index by name for this value currently.
            element[DNS_SERVICES_STR].update(dnsservices_template)
        delete_if_empty(element, DNS_SERVICES_STR)

        # Get Application Probes
        element[APPLICATION_PROBE_STR] = {}
        response = sdk.get.application_probe(site['id'], element['id'])
        error = response.cgx_content.get('_error', None)
        # Check for the error code. If the element version does not support app_probe, ignore the error
        if error:
            if error[0].get('code') not in ('APPLICATION_PROBE_CONFIG_UNSUPPORTED_SWVERSION', 'APPLICATION_PROBE_CONFIG_NOT_PRESENT'):
                throw_error("Application probe get failed: ", response)
        else:
            app_probe = response.cgx_content
            id_name_cache.update(build_lookup_dict([app_probe], key_val='id', value_val='name'))
            app_probe_template = copy.deepcopy(app_probe)
            app_probe_source_interface_id = app_probe_template.get('source_interface_id')
            bps = ''
            # Add 'parent_type' field if model is 9k and interface is bypasspair
            if if_id2type.get(app_probe_source_interface_id) == 'bypasspair':
                bps += '_' + id_name_cache.get(app_probe_source_interface_id)
                app_probe_template['parent_type'] = 'bypasspair' + bps
            name_lookup_in_template(app_probe_template, 'source_interface_id', id_name_cache)
            strip_meta_attributes(app_probe_template, leave_name=True)

            # names used, but config doesn't index by name for this value currently.
            element[APPLICATION_PROBE_STR].update(app_probe_template)
        delete_if_empty(element, APPLICATION_PROBE_STR)

        # Get Ipfix configs
        element[IPFIX_STR] = {}
        response = sdk.get.ipfix(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Ipfix get failed: ", response)

        ipfix_all = response.cgx_content['items']
        id_name_cache.update(build_lookup_dict(ipfix_all, key_val='id', value_val='name'))
        for ipfix in ipfix_all:
            ipfix_template = copy.deepcopy(ipfix)
            name_lookup_in_template(ipfix_template, 'ipfixprofile_id', id_name_cache)
            name_lookup_in_template(ipfix_template, 'ipfixtemplate_id', id_name_cache)
            if ipfix_template.get('collector_config', []):
                for config in ipfix_template.get('collector_config', []):
                    name_lookup_in_template(config, 'ipfixcollectorcontext_id', id_name_cache)
            if ipfix_template.get('filters', []):
                for filter_context in ipfix_template.get('filters', []):
                    name_lookup_in_template(filter_context, 'src_prefixes_id', id_name_cache)
                    name_lookup_in_template(filter_context, 'dst_prefixes_id', id_name_cache)

                    filter_context_id_list, app_def_id_list = [], []
                    if filter_context.get('ipfixfiltercontext_ids', []):
                        for filter_context_id in filter_context.get('ipfixfiltercontext_ids', []):
                            filter_context_id_list.append(id_name_cache.get(filter_context_id, filter_context_id))
                        if filter_context_id_list:
                            filter_context['ipfixfiltercontext_ids'] = filter_context_id_list

                    for app_def_id in filter_context.get('app_def_ids', []):
                        app_def_id_list.append(id_name_cache.get(app_def_id, app_def_id))
                    if app_def_id_list:
                        filter_context['app_def_ids'] = app_def_id_list

            strip_meta_attributes(ipfix_template, leave_name=True)
            # names used, but config doesn't index by name for this value currently.
            element[IPFIX_STR].update(ipfix_template)
        delete_if_empty(element, IPFIX_STR)

        # Get toolkit
        response = sdk.get.elementaccessconfigs(element['id'])
        if not response.cgx_status:
            throw_error("Toolkit get failed: ", response)
        elementaccessconfig = response.cgx_content
        elementaccessconfig_template = copy.deepcopy(elementaccessconfig)
        strip_meta_attributes(elementaccessconfig_template)
        # no name field for this item
        element[TOOLKIT_STR] = elementaccessconfig_template
        # toolkit should never be empty, but just in case:
        delete_if_empty(element, TOOLKIT_STR)

        # Add the element
        element_template = copy.deepcopy(element)
        strip_meta_attributes(element_template)

        # remove other element items that are redundant in this config
        if element_template.get('site_id'):
            del element_template['site_id']
        if element_template.get('hw_id'):
            # use serial_number not HWID, machine config will use this value too
            del element_template['hw_id']

        # replace complex name for spoke_ha_config
        spoke_ha_config = element_template.get('spoke_ha_config')
        if spoke_ha_config:
            # need to look for names
            spoke_ha_config_template = copy.deepcopy(spoke_ha_config)
            name_lookup_in_template(spoke_ha_config_template, 'cluster_id', id_name_cache)
            name_lookup_in_template(spoke_ha_config_template, 'source_interface', id_name_cache)
            spoke_ha_config_track = spoke_ha_config.get('track')
            if spoke_ha_config_track:
                spoke_ha_config_track_template = copy.deepcopy(spoke_ha_config_track)
                spoke_ha_config_track_interfaces = spoke_ha_config_track.get("interfaces")
                if spoke_ha_config_track_interfaces:
                    spoke_ha_config_track_interfaces_template = []
                    for spoke_ha_config_track_interfaces_entry in spoke_ha_config_track_interfaces:
                        spoke_ha_config_track_interfaces_entry_template = \
                            copy.deepcopy(spoke_ha_config_track_interfaces_entry)
                        name_lookup_in_template(spoke_ha_config_track_interfaces_entry_template,
                                                'interface_id', id_name_cache)
                        spoke_ha_config_track_interfaces_template.append(spoke_ha_config_track_interfaces_entry_template)
                    spoke_ha_config_track_template['interfaces'] = spoke_ha_config_track_interfaces_template
                spoke_ha_config_template['track'] = spoke_ha_config_track_template
            element_template['spoke_ha_config'] = spoke_ha_config_template

        # check for duplicate names
        checked_element_name = check_name(element['name'], dup_name_dict_elements, 'Element',
                                          error_site_txt="{0}({1})".format(error_site_name,
                                                                           site_id))
        # update id name cache in case name changed.
        id_name_cache[element['id']] = checked_element_name
        site[ELEMENTS_STR][checked_element_name] = element_template
        # as always, sanity check for empty element
        delete_if_empty(site[ELEMENTS_STR], checked_element_name)

    # prep for add to sites dict
    site_template = copy.deepcopy(site)

    # replace flat names
    name_lookup_in_template(site_template, 'policy_set_id', id_name_cache)
    name_lookup_in_template(site_template, 'security_policyset_id', id_name_cache)
    name_lookup_in_template(site_template, 'security_policysetstack_id', id_name_cache)
    name_lookup_in_template(site_template, 'network_policysetstack_id', id_name_cache)
    name_lookup_in_template(site_template, 'priority_policysetstack_id', id_name_cache)
    name_lookup_in_template(site_template, 'service_binding', id_name_cache)
    name_lookup_in_template(site_template, 'nat_policysetstack_id', id_name_cache)

    strip_meta_attributes(site_template)
    # check for duplicate names
    checked_site_name = check_name(site['name'], dup_name_dict_sites, 'Site')
    # update id name cache in case name changed.
    id_name_cache[site['id']] = checked_site_name
    CONFIG[SITES_STR][checked_site_name] = site_template
    # as always, sanity check for empty site
    delete_if_empty(CONFIG[SITES_STR], checked_site_name)
    return


def pull_config_sites(sites, output_filename, output_multi=None, passed_sdk=None, passed_report_id=None,
                      passed_strip_versions=None, passed_force_parents=None, no_header=None, return_result=False,
                      normalize=False):
    """
    Main configuration pull function
    :param sites: Comma seperated list of site names or IDs, or "ALL_SITES" text.
    :param output_filename: Filename to save configuration YAML content to.
    :param output_multi: If set, creates one file per site(s), using 'site name.yml' as filename in specified value
                         (which should be a directory path).
    :param passed_sdk: A cloudgenix.API() authenticated SDK object. Required if running function from external script.
    :param passed_report_id: Optional - Report ID in YAML, default False
    :param passed_strip_versions: Optional - Remove API versions from YAML, default False
    :param passed_force_parents: Optional - Leave unconfigurable parent interfaces in configuration, default False.
    :param no_header: Optional - bool, Remove metadata header from YAML file. True removes, False or None keep.
    :param return_result: Optional - bool, If True, return the result as a Dict instead of writing out to YAML file.
    :param normalize: Optional - bool, if true, make sure site name is renamed to safe name.
    :return: Default - directly writes YAML file to output_filename specified, no return.
    """
    global ELEMENTS
    global SITES
    global CONFIG
    global REPORT_ID
    global STRIP_VERSIONS
    global FORCE_PARENTS
    global sdk

    # check passed vars
    if passed_sdk is not None:
        sdk = passed_sdk
    if passed_report_id is not None:
        REPORT_ID = passed_report_id
    if passed_strip_versions is not None:
        STRIP_VERSIONS = passed_strip_versions
    if passed_force_parents is not None:
        FORCE_PARENTS = passed_force_parents

    # update all caches
    update_global_cache()

    # Get version output strings
    build_version_strings()

    ELEMENTS = elements_cache
    SITES = sites_cache
    CONFIG[SITES_STR] = {}

    sdk_version = cloudgenix.version
    if 'v' in sdk_version:
        sdk_version.replace('v', '')
    config_version = import_cloudgenix_config_version
    if 'v' in config_version:
        config_version.replace('v', '')

    if sites is None:
        # no site specified.
        throw_error("A 'Site Name', comma-seperated list of sites 'Site A, Site B', or "
                    "'ALL_SITES' must be specified to the mandatory '--sites/-S' option.")

    if output_multi is None or return_result:
        # single site, specified file, or API call asking to return object. Ignore output_multi if
        # return_result is set.
        if sites == "ALL_SITES":
            for val in SITES:
                _pull_config_for_single_site(val['id'])
            if not CONFIG[SITES_STR]:
                # got no config info.
                throw_error("No matching sites found when attempting to pull config for ALL_SITES.\n"
                            "Exiting.")
        else:
            for val in sites.split(','):
                # ensure removing leading/trailing whitespace
                _pull_config_for_single_site(val.strip())
            if not CONFIG[SITES_STR]:
                # got no config info.
                throw_error("No matching site found that matched entered site(s): \n"
                            "\t{0}\n"
                            "Exiting.".format(val))

        # Got here, we got some site data.
        # Fix for CGCL-565. Adding sdk_version and config_version keys in yml
        # if not set to return_obj, write out YAML file.
        if return_result:
            # add headers to CONFIG.
            CONFIG['type'] = "cloudgenix template"
            if sdk_version >= SDK_VERSION_REQUIRED and config_version >= CONFIG_VERSION_REQUIRED:
                CONFIG['sdk_version'] = sdk_version
                CONFIG['config_version'] = config_version
            return CONFIG
        else:
            config_yml = open(output_filename, "w")
            config_yml.write("---\ntype: cloudgenix template\n")
            if sdk_version >= SDK_VERSION_REQUIRED and config_version >= CONFIG_VERSION_REQUIRED:
                config_yml.write(f"sdk_version: {sdk_version}\n")
                config_yml.write(f"config_version: {config_version}\n")
            # write header by default, but skip if asked.
            if not no_header:
                config_yml.write("# Created at {0}\n".format(datetime.datetime.utcnow().isoformat()+"Z"))
                if sdk.email:
                    config_yml.write("# by {0}\n".format(sdk.email))
            config_yml.write("# Note: For interface configuration, if the source_interface or parent_interface is a bypasspair port, add the attribute 'parent_type': bypasspair_<name> where name is the interface name. \n# If this field is not specified, the cloudgenix_config utility will assume the parent interface is of type 'port'.\n")
            # Adding FROM_CLOUDBLADE line into pull site yml file
            if FROM_CLOUDBLADE:
                config_yml.write("# FROM_CLOUDBLADE\n")
            yaml.safe_dump(CONFIG, config_yml, default_flow_style=False)
            config_yml.close()

            # jd(CONFIG)
            # jd(id_name_cache)
    else:
        # output_multi is set. Prepare.

        # make sure directory works.
        final_dir = os.path.join(output_multi, '')
        try:
            os.mkdir(final_dir)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            pass

        # single site, specified file.
        if sites == "ALL_SITES":

            for val in SITES:
                # Reset config
                CONFIG[SITES_STR] = {}
                _pull_config_for_single_site(val['id'])
                if not CONFIG[SITES_STR]:
                    # got no config info.
                    throw_error("No matching sites found when attempting to pull config for ALL_SITES.\n"
                                "Exiting.")
                # should only be one site in config
                cur_site_count = len(CONFIG[SITES_STR])
                if cur_site_count != 1:
                    throw_error("BUG: Got more than one site in single site object, Exiting.")
                # extract site name
                cur_site_name = list(CONFIG[SITES_STR].keys())[0]

                if normalize:
                    final_site_name = "".join(x for x in cur_site_name if (x.isalnum() or x in "._- "))
                    # remove spaces
                    final_site_name = final_site_name.replace(' ', '_')
                else:
                    final_site_name = cur_site_name

                # Write out YAML file.
                config_yml = open(final_dir + final_site_name + ".yml", "w")
                config_yml.write("---\ntype: cloudgenix template\n")
                if sdk_version >= SDK_VERSION_REQUIRED and config_version >= CONFIG_VERSION_REQUIRED:
                    config_yml.write(f"sdk_version: {sdk_version}\n")
                    config_yml.write(f"config_version: {config_version}\n")
                # write header by default, but skip if asked.
                if not no_header:
                    config_yml.write("# Created at {0}\n".format(datetime.datetime.utcnow().isoformat()+"Z"))
                    if sdk.email:
                        config_yml.write("# by {0}\n".format(sdk.email))
                config_yml.write("# Note: For interface configuration, if the source_interface or parent_interface is a bypasspair port, add the attribute 'parent_type': bypasspair_IF1_IF2 and so on. \n# If this field is not specified, the cloudgenix_config utility will assume the parent interface is of type 'port'.\n")
                yaml.safe_dump(CONFIG, config_yml, default_flow_style=False)
                config_yml.close()

                # jd(CONFIG)
                # jd(id_name_cache)

        else:

            for val in sites.split(','):
                # Reset config
                CONFIG[SITES_STR] = {}
                # ensure removing leading/trailing whitespace
                _pull_config_for_single_site(val.strip())
                if not CONFIG[SITES_STR]:
                    # got no config info.
                    throw_error("No matching site found that matched entered site(s): \n"
                                "\t{0}\n"
                                "Exiting.".format(val))

                # should only be one site in config
                cur_site_count = len(CONFIG[SITES_STR])
                if cur_site_count != 1:
                    throw_error("BUG: Got more than one site in single site object, Exiting.")
                # extract site name
                cur_site_name = list(CONFIG[SITES_STR].keys())[0]

                if normalize:
                    final_site_name = "".join(x for x in cur_site_name if (x.isalnum() or x in "._- "))
                    # remove spaces
                    final_site_name = final_site_name.replace(' ', '_')
                else:
                    final_site_name = cur_site_name

                # Write out YAML file.
                config_yml = open(final_dir + final_site_name + ".yml", "w")
                config_yml.write("---\ntype: cloudgenix template\n")
                if sdk_version >= SDK_VERSION_REQUIRED and config_version >= CONFIG_VERSION_REQUIRED:
                    config_yml.write(f"sdk_version: {sdk_version}\n")
                    config_yml.write(f"config_version: {config_version}\n")
                # write header by default, but skip if asked.
                if not no_header:
                    config_yml.write("# Created at {0}\n".format(datetime.datetime.utcnow().isoformat()+"Z"))
                    if sdk.email:
                        config_yml.write("# by {0}\n".format(sdk.email))
                config_yml.write("# Note: For interface configuration, if the source_interface or parent_interface is a bypasspair port, add the attribute 'parent_type': bypasspair_IF1_IF2 and so on. \n# If this field is not specified, the cloudgenix_config utility will assume the parent interface is of type 'port'.\n")
                yaml.safe_dump(CONFIG, config_yml, default_flow_style=False)
                config_yml.close()

                # jd(CONFIG)
                # jd(id_name_cache)

    return


def go():
    """
    Stub script entry point. Authenticates CloudGenix SDK, and gathers options from command line to run
    pull_config_sites()
    :return: No return
    """
    global ELEMENTS
    global SITES
    global CONFIG
    global REPORT_ID
    global STRIP_VERSIONS
    global FORCE_PARENTS
    global sdk

    parser = argparse.ArgumentParser()
    # Allow Controller modification and debug level sets.
    config_group = parser.add_argument_group('Config', 'These options change how the configuration is generated.')
    config_group.add_argument('--sites', '-S',
                              help='Site name or id. More than one can be specified '
                                   'separated by comma, or special string "ALL_SITES".',
                              required=True)
    config_group.add_argument('--leave-implicit-ids',
                              help='Preserve implicit IDs in objects ("id" values only, '
                                   'references to other objects will still be names.)',
                              default=False, action="store_true")
    config_group.add_argument('--strip-versions',
                              help='Output non-versioned configuration branches.',
                              default=False, action="store_true")
    config_group.add_argument("--force-parents", help="Force export of parent interface configurations.",
                              default=False, action="store_true")
    config_group.add_argument("--no-header", help="Skip export of Metadata header in config YAML.",
                              default=False, action="store_true")

    config_group.add_argument("--normalize", help="Normalize the site name to filesystem friendly. Only has effect "
                                                  "with --multi-out.",
                              default=False, action="store_true")

    file_output = config_group.add_mutually_exclusive_group()

    file_output.add_argument("--output", help="Output file name (default './config.yml')", type=str,
                             default="./config.yml")
    file_output.add_argument("--multi-output", help="Enable per-site file output. Specify Directory to place file(s).",
                             type=str, default=None)

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. https://api.elcapitan.cloudgenix.com",
                                  default=None)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of cloudgenix_settings.py "
                                                   "or prompting",
                             default=None)
    login_group.add_argument("--password", "-PW", help="Use this Password instead of cloudgenix_settings.py "
                                                       "or prompting",
                             default=None)
    login_group.add_argument("--insecure", "-I", help="Do not verify SSL certificate",
                             action='store_true',
                             default=False)
    login_group.add_argument("--noregion", "-NR", help="Ignore Region-based redirection.",
                             dest='ignore_region', action='store_true', default=False)

    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    group = debug_group.add_mutually_exclusive_group()
    group.add_argument("--rest", "-R", help="Show REST requests",
                       action='store_true',
                       default=False)
    debug_group.add_argument("--debug", "-D", help="API Debug info, levels 0-2",
                             type=int, default=0)
    debug_group.add_argument("--version", help="Dump Version(s) of script and modules and exit.", action='version',
                             version=dump_version())

    args = vars(parser.parse_args())

    REPORT_ID = args['leave_implicit_ids']
    STRIP_VERSIONS = args['strip_versions']
    FORCE_PARENTS = args['force_parents']
    filename = args['output']
    multi_output = args['multi_output']
    normalize = args['normalize']

    # Build SDK Constructor
    if args['controller'] and args['insecure']:
        sdk = cloudgenix.API(controller=args['controller'], ssl_verify=False)
    elif args['controller']:
        sdk = cloudgenix.API(controller=args['controller'])
    elif args['insecure']:
        sdk = cloudgenix.API(ssl_verify=False)
    else:
        sdk = cloudgenix.API()

    # check for region ignore
    if args['ignore_region']:
        sdk.ignore_region = True

    if args['debug']:
        sdk.set_debug(int(args['debug']))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["password"]:
        user_password = args["password"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["password"]:
        sdk.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if sdk.tenant_id is None:
            throw_error("AUTH_TOKEN login failure, please check token.")

    else:
        while sdk.tenant_id is None:
            sdk.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not sdk.tenant_id:
                user_email = None
                user_password = None

    # pull the specified sites config
    pull_config_sites(args['sites'], filename, output_multi=multi_output, normalize=normalize,
                      no_header=args['no_header'])

    return


if __name__ == '__main__':
    go()
