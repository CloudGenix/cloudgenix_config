# -*- coding: utf-8 -*-
"""
Configuration EXPORT worker/script

**Version:** v1.0.0b1

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
import re
import sys
import os
import argparse
import copy
import datetime
import logging

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
from cloudgenix_config import throw_error, throw_warning, name_lookup_in_template, extract_items, build_lookup_dict, \
    check_name, nameable_interface_types, skip_interface_list, get_function_default_args

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


# replace NULL exported YAML values with blanks. Semantically the same, but easier to read.
def represent_none(self, _):
    return self.represent_scalar('tag:yaml.org,2002:null', '')


yaml.add_representer(type(None), represent_none, Dumper=yaml.SafeDumper)


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
ELEMENT_EXTENSIONS_STR = "element_extensions"
DHCP_SERVERS_STR = "dhcpservers"
BGP_GLOBAL_CONFIG_STR = "global_config"
BGP_PEERS_CONFIG_STR = "peers"
ROUTEMAP_CONFIG_STR = "route_maps"
ASPATHACL_CONFIG_STR = "as_path_access_lists"
PREFIXLISTS_CONFIG_STR = "prefix_lists"
IPCOMMUNITYLISTS_CONFIG_STR = "ip_community_lists"
HUBCLUSTER_CONFIG_STR = "hubclusters"


# Global Config Cache holders
sites_cache = []
elements_cache = []
machines_cache = []
policysets_cache = []
security_policysets_cache = []
network_policysetstack_cache = []
priority_policysetstack_cache = []
waninterfacelabels_cache = []
wannetworks_cache = []
servicebindingmaps_cache = []
serviceendpoints_cache = []
ipsecprofiles_cache = []
networkcontexts_cache = []
appdefs_cache = []
id_name_cache = {}
sites_n2id = {}
dup_name_dict_sites = {}

# Define constructor globally for now.
cgx_session = cloudgenix.API()
jd = cloudgenix.jd

# Set logging to use function name
logger = logging.getLogger(__name__)

idreg = re.compile('^[0-9]+$')


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
    global network_policysetstack_cache
    global priority_policysetstack_cache
    global waninterfacelabels_cache
    global wannetworks_cache
    global servicebindingmaps_cache
    global serviceendpoints_cache
    global ipsecprofiles_cache
    global networkcontexts_cache
    global appdefs_cache
    global id_name_cache
    global sites_n2id

    # sites
    sites_resp = cgx_session.get.sites()
    sites_cache, _ = extract_items(sites_resp, 'sites')

    # elements
    elements_resp = cgx_session.get.elements()
    elements_cache, _ = extract_items(elements_resp, 'elements')

    # machines
    machines_resp = cgx_session.get.machines()
    machines_cache, _ = extract_items(machines_resp, 'machines')

    # policysets
    policysets_resp = cgx_session.get.policysets()
    policysets_cache, _ = extract_items(policysets_resp, 'policysets')

    # secuirity_policysets
    security_policysets_resp = cgx_session.get.securitypolicysets()
    security_policysets_cache, _ = extract_items(security_policysets_resp, 'secuirity_policysets')

    # network_policysetstack
    network_policysetstack_resp = cgx_session.get.networkpolicysetstacks()
    network_policysetstack_cache, _ = extract_items(network_policysetstack_resp, 'network_policysetstack')

    # prioroty_policysetstack
    prioroty_policysetstack_resp = cgx_session.get.prioritypolicysetstacks()
    prioroty_policysetstack_cache, _ = extract_items(prioroty_policysetstack_resp, 'prioroty_policysetstack')

    # waninterfacelabels
    waninterfacelabels_resp = cgx_session.get.waninterfacelabels()
    waninterfacelabels_cache, _ = extract_items(waninterfacelabels_resp, 'waninterfacelabels')

    # wannetworks
    wannetworks_resp = cgx_session.get.wannetworks()
    wannetworks_cache, _ = extract_items(wannetworks_resp, 'wannetworks')

    # servicebindingmaps
    servicebindingmaps_resp = cgx_session.get.servicebindingmaps()
    servicebindingmaps_cache, _ = extract_items(servicebindingmaps_resp, 'servicebindingmaps')

    # serviceendpoints
    serviceendpoints_resp = cgx_session.get.serviceendpoints()
    serviceendpoints_cache, _ = extract_items(serviceendpoints_resp, 'serviceendpoints')

    # ipsecprofiles
    ipsecprofiles_resp = cgx_session.get.ipsecprofiles()
    ipsecprofiles_cache, _ = extract_items(ipsecprofiles_resp, 'ipsecprofiles')

    # networkcontexts
    networkcontexts_resp = cgx_session.get.networkcontexts()
    networkcontexts_cache, _ = extract_items(networkcontexts_resp, 'networkcontexts')

    # appdef
    appdefs_resp = cgx_session.get.appdefs()
    appdefs_cache, _ = extract_items(appdefs_resp, 'appdefs')

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

    # network_policysetstack name
    id_name_cache.update(build_lookup_dict(network_policysetstack_cache, key_val='id', value_val='name'))

    # prioroty_policysetstack name
    id_name_cache.update(build_lookup_dict(prioroty_policysetstack_cache, key_val='id', value_val='name'))

    # waninterfacelabels name
    id_name_cache.update(build_lookup_dict(waninterfacelabels_cache, key_val='id', value_val='name'))

    # wannetworks name
    id_name_cache.update(build_lookup_dict(wannetworks_cache, key_val='id', value_val='name'))

    # servicebindingmaps name
    id_name_cache.update(build_lookup_dict(servicebindingmaps_cache, key_val='id', value_val='name'))

    # serviceendpoints name
    id_name_cache.update(build_lookup_dict(serviceendpoints_cache, key_val='id', value_val='name'))

    # ipsecprofiles name
    id_name_cache.update(build_lookup_dict(ipsecprofiles_cache, key_val='id', value_val='name'))

    # networkcontexts name
    id_name_cache.update(build_lookup_dict(networkcontexts_cache, key_val='id', value_val='name'))

    # appdefs name
    id_name_cache.update(build_lookup_dict(appdefs_cache, key_val='id', value_val='name'))

    return


def add_version_to_object(cgx_session_func, input_string):
    """
    Adds API version as version key to string
    :param cgx_session_func: CloudGenix CGX_SESSION function
    :param input_string: Config section
    :return: input_string + ' ' + API version.
    """
    args = get_function_default_args(cgx_session_func)
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
    global ELEMENT_EXTENSIONS_STR
    global DHCP_SERVERS_STR
    global BGP_GLOBAL_CONFIG_STR
    global BGP_PEERS_CONFIG_STR
    global ROUTEMAP_CONFIG_STR
    global ASPATHACL_CONFIG_STR
    global PREFIXLISTS_CONFIG_STR
    global IPCOMMUNITYLISTS_CONFIG_STR
    global HUBCLUSTER_CONFIG_STR

    if not STRIP_VERSIONS:
        # Config container strings
        SITES_STR = add_version_to_object(cgx_session.get.sites, "sites")
        ELEMENTS_STR = add_version_to_object(cgx_session.get.elements, "elements")
        WANINTERFACES_STR = add_version_to_object(cgx_session.get.waninterfaces, "waninterfaces")
        LANNETWORKS_STR = add_version_to_object(cgx_session.get.lannetworks, "lannetworks")
        INTERFACES_STR = add_version_to_object(cgx_session.get.interfaces, "interfaces")
        STATIC_STR = add_version_to_object(cgx_session.get.staticroutes, "static")
        AGENT_STR = add_version_to_object(cgx_session.get.snmpagents, "agent")
        TRAPS_STR = add_version_to_object(cgx_session.get.snmptraps, "traps")
        NTP_STR = add_version_to_object(cgx_session.get.ntp, "ntp")
        SYSLOG_STR = add_version_to_object(cgx_session.get.syslogservers, "syslog")
        TOOLKIT_STR = add_version_to_object(cgx_session.get.elementaccessconfigs, "toolkit")
        ELEMENT_EXTENSIONS_STR = add_version_to_object(cgx_session.get.element_extensions, "element_extensions")
        DHCP_SERVERS_STR = add_version_to_object(cgx_session.get.dhcpservers, "dhcpservers")
        BGP_GLOBAL_CONFIG_STR = add_version_to_object(cgx_session.get.bgpconfigs, "global_config")
        BGP_PEERS_CONFIG_STR = add_version_to_object(cgx_session.get.bgppeers, "peers")
        ROUTEMAP_CONFIG_STR = add_version_to_object(cgx_session.get.routing_routemaps, "route_maps")
        ASPATHACL_CONFIG_STR = add_version_to_object(cgx_session.get.routing_aspathaccesslists, "as_path_access_lists")
        PREFIXLISTS_CONFIG_STR = add_version_to_object(cgx_session.get.routing_prefixlists, "prefix_lists")
        IPCOMMUNITYLISTS_CONFIG_STR = add_version_to_object(cgx_session.get.routing_ipcommunitylists,
                                                            "ip_community_lists")
        HUBCLUSTER_CONFIG_STR = add_version_to_object(cgx_session.get.routing_prefixlists, "hubclusters")


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
        if not val and not isinstance(val, bool) and val is not 0:
            variable_dict.pop(key)
    return


def _pull_config_for_single_site(site_name_id):
    """
    Function to pull configuration from CloudGenix controller, and save as YAML file.
    Needs cloudgenix_config globals set (cgx_session, cache, etc). Rework eventually to allow running
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

    # Get WAN interfaces
    dup_name_dict = {}
    site[WANINTERFACES_STR] = {}
    response = cgx_session.get.waninterfaces(site['id'])
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
        strip_meta_attributes(waninterface_template)
        # check name for duplicates
        checked_wannetwork_name = check_name(ui_normalized_name, dup_name_dict, 'Waninterface')
        # update id name cache in case name changed.
        id_name_cache[waninterface['id']] = checked_wannetwork_name
        site[WANINTERFACES_STR][checked_wannetwork_name] = waninterface_template
    delete_if_empty(site, WANINTERFACES_STR)

    # Get LAN Networks
    dup_name_dict = {}
    site[LANNETWORKS_STR] = {}
    response = cgx_session.get.lannetworks(site['id'])
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
        checked_lannetwork_name = check_name(lannetwork['name'], dup_name_dict, 'Laninterface')
        # update id name cache in case name changed.
        id_name_cache[lannetwork['id']] = checked_lannetwork_name
        site[LANNETWORKS_STR][checked_lannetwork_name] = lannetwork_template
    delete_if_empty(site, LANNETWORKS_STR)

    # Get Hub Clusters
    dup_name_dict = {}
    site[HUBCLUSTER_CONFIG_STR] = {}
    response = cgx_session.get.hubclusters(site['id'])
    if not response.cgx_status:
        throw_error("LAN networks get failed: ", response)
    hubclusters = response.cgx_content['items']
    # update id_name_cache
    id_name_cache.update(build_lookup_dict(hubclusters, key_val='id', value_val='name'))
    for hubcluster in hubclusters:
        hubcluster_template = copy.deepcopy(hubcluster)
        name_lookup_in_template(hubcluster_template, 'network_context_id', id_name_cache)
        name_lookup_in_template(hubcluster_template, 'security_policy_set', id_name_cache)
        strip_meta_attributes(hubcluster_template)
        # check name for duplicates
        checked_hubcluster_name = check_name(hubcluster['name'], dup_name_dict, 'Laninterface')
        # update id name cache in case name changed.
        id_name_cache[hubcluster['id']] = checked_hubcluster_name
        site[HUBCLUSTER_CONFIG_STR][checked_hubcluster_name] = hubcluster_template
    delete_if_empty(site, HUBCLUSTER_CONFIG_STR)

    # Get DHCP Servers
    site[DHCP_SERVERS_STR] = []
    response = cgx_session.get.dhcpservers(site['id'])
    if not response.cgx_status:
        throw_error("DHCP Servers networks get failed: ", response)
    dhcpservers = response.cgx_content['items']

    for dhcpserver in dhcpservers:
        dhcpserver_template = copy.deepcopy(dhcpserver)
        name_lookup_in_template(dhcpserver_template, 'network_context_id', id_name_cache)
        strip_meta_attributes(dhcpserver_template)
        # no names, don't need duplicate check
        site[DHCP_SERVERS_STR].append(dhcpserver_template)
    delete_if_empty(site, DHCP_SERVERS_STR)

    # Get Elements
    site[ELEMENTS_STR] = {}
    dup_name_dict_elements = {}
    for element in ELEMENTS:
        if element['site_id'] != site['id']:
            continue

        # Get interfaces
        element[INTERFACES_STR] = {}
        dup_name_dict = {}
        response = cgx_session.get.interfaces(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Element interfaces get failed: ", response)
        interfaces = response.cgx_content['items']
        # update id_name_cache
        id_name_cache.update(build_lookup_dict(interfaces, key_val='id', value_val='name'))

        # create a parent list
        parent_id_list = []
        for interface in interfaces:
            parent_id = interface.get('parent')
            if_type = interface.get('type')
            if parent_id is not None and if_type in ['subinterface', 'pppoe', 'port']:
                # add to parent list if it is not a service link, as service link if configs can be modified.
                # print("INTERFACE {0} is PARENT: {1}".format(parent_id, jdout(interface)))
                parent_id_list.append(parent_id)
            bypasspair_config = interface.get('bypass_pair')
            if bypasspair_config is not None and isinstance(bypasspair_config, dict):
                wan_id = bypasspair_config.get('wan')
                lan_id = bypasspair_config.get('lan')
                if wan_id is not None:
                    # add to parent list
                    parent_id_list.append(wan_id)
                if lan_id is not None:
                    # add to parent list
                    parent_id_list.append(lan_id)

        for interface in interfaces:
            interface_id = interface.get('id')
            if not FORCE_PARENTS and interface_id in parent_id_list:
                # interface is a parent, skip
                continue
            if not FORCE_PARENTS and interface.get('name') in skip_interface_list:
                # Unconfigurable interface, skip.
                continue
            # Update ids to names for complex objects in interfaces first
            interface_template = copy.deepcopy(interface)
            swi_list = interface.get('site_wan_interface_ids', None)
            if swi_list and isinstance(swi_list, list):
                swi_template = []
                for swi_id in swi_list:
                    swi_template.append(id_name_cache.get(swi_id, swi_id))
                interface_template['site_wan_interface_ids'] = swi_template

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

            # replace flat names in interface itself
            name_lookup_in_template(interface_template, 'parent', id_name_cache)

            # strip metadata/names
            strip_meta_attributes(interface_template)
            # ok. Check for duplicates if it is a namable interface. If a dup is found, rename.
            interface_type = interface_template.get('type', "Unknown Interface")
            if interface_type in nameable_interface_types:
                checked_interface_name = check_name(interface['name'], dup_name_dict, interface_type)
                # update id name cache in case name changed.
                id_name_cache[interface['id']] = checked_interface_name
                element[INTERFACES_STR][checked_interface_name] = interface_template
            else:
                element[INTERFACES_STR][interface['name']] = interface_template

        element['routing'] = {}

        # Get static routes
        element['routing'][STATIC_STR] = []
        response = cgx_session.get.staticroutes(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Static routes get failed: ", response)
        staticroutes = response.cgx_content['items']
        for staticroute in staticroutes:
            staticroute_template = copy.deepcopy(staticroute)
            nexthops = staticroute.get('nexthops')
            if nexthops and isinstance(nexthops, list):
                nexthops_template = []
                for nexthop in nexthops:
                    nexthop_template = copy.deepcopy(nexthop)
                    # replace flat names in dict
                    name_lookup_in_template(nexthop_template, 'nexthop_interface_id', id_name_cache)
                    # add to list
                    nexthops_template.append(nexthop_template)
                staticroute_template['nexthops'] = nexthops_template

            strip_meta_attributes(staticroute_template)
            # no names, don't need dupliate check
            element['routing'][STATIC_STR].append(staticroute_template)
        delete_if_empty(element, STATIC_STR)

        # Get BGP configuration
        element['routing']['bgp'] = {}

        # grab all queries now so we can update id_name_cache.
        bgp_global_response = cgx_session.get.bgpconfigs(site['id'], element['id'])
        bgp_global_cache, _ = extract_items(bgp_global_response, 'bgp_global_config')

        bgp_peers_response = cgx_session.get.bgppeers(site['id'], element['id'])
        bgp_peers_cache, _ = extract_items(bgp_peers_response, 'bgp_peer_config')

        routemaps_response = cgx_session.get.routing_routemaps(site['id'], element['id'])
        routemaps_cache, _ = extract_items(routemaps_response, 'routemap_config')

        aspath_access_lists_response = cgx_session.get.routing_aspathaccesslists(site['id'], element['id'])
        aspath_access_lists_cache, _ = extract_items(aspath_access_lists_response, 'aspath_access_list_config')

        routing_prefixlists_response = cgx_session.get.routing_prefixlists(site['id'], element['id'])
        routing_prefixlists_cache, _ = extract_items(routing_prefixlists_response, 'routing_prefixlists_config')

        ip_community_lists_response = cgx_session.get.routing_ipcommunitylists(site['id'], element['id'])
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
            checked_bgp_peer_name = check_name(bgp_peer['name'], dup_name_dict, 'BGP Peer')
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
            checked_routemap_name = check_name(routemap['name'], dup_name_dict, 'Route Map')
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
                                                         'AS-PATH Access List')
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
            checked_routing_prefixlist_name = check_name(routing_prefixlist['name'], dup_name_dict, 'Prefix List')
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
            checked_ip_community_list_name = check_name(ip_community_list['name'], dup_name_dict, 'IP-Community List')
            # update id name cache in case name changed.
            id_name_cache[ip_community_list['id']] = checked_ip_community_list_name
            element['routing'][IPCOMMUNITYLISTS_CONFIG_STR][checked_ip_community_list_name] = ip_community_list_template
        delete_if_empty(element['routing'], IPCOMMUNITYLISTS_CONFIG_STR)

        # Check for completely empty routing:
        delete_if_empty(element, 'routing')

        # Get syslog
        element[SYSLOG_STR] = []
        response = cgx_session.get.syslogservers(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Syslog servers get failed: ", response)
        syslogservers = response.cgx_content['items']
        for syslogserver in syslogservers:
            syslogserver_template = copy.deepcopy(syslogserver)
            # replace flat name
            name_lookup_in_template(syslogserver_template, 'source_interface', id_name_cache)
            strip_meta_attributes(syslogserver_template, leave_name=True)
            # names used, but config doesn't index by name for this value currently.
            element[SYSLOG_STR].append(syslogserver_template)
        delete_if_empty(element, SYSLOG_STR)

        # Get NTP configs
        element[NTP_STR] = []
        response = cgx_session.get.ntp(element['id'])
        if not response.cgx_status:
            throw_error("NTP config get failed: ", response)
        ntps = response.cgx_content['items']
        for ntp in ntps:
            ntp_template = copy.deepcopy(ntp)
            strip_meta_attributes(ntp_template, leave_name=True)
            # names used, but config doesn't index by name for this value currently.
            element[NTP_STR].append(ntp_template)
        delete_if_empty(element, NTP_STR)

        # Get element_extension configs
        element[ELEMENT_EXTENSIONS_STR] = {}
        dup_name_dict = {}
        response = cgx_session.get.element_extensions(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("Element Extension config get failed: ", response)
        element_extensions = response.cgx_content['items']
        for element_extension in element_extensions:
            element_extension_template = copy.deepcopy(element_extension)
            # replace flat name
            name_lookup_in_template(element_extension_template, 'entity_id', id_name_cache)
            strip_meta_attributes(element_extension_template)
            # check for duplicate names
            checked_element_extension_name = check_name(element_extension['name'], dup_name_dict, 'Element Extension')
            # update id name cache in case name changed.
            id_name_cache[element_extension['id']] = checked_element_extension_name
            element[ELEMENT_EXTENSIONS_STR][checked_element_extension_name] = element_extension_template
        delete_if_empty(element, ELEMENT_EXTENSIONS_STR)

        # start SNMP section
        element['snmp'] = {}

        # Get SNMP Traps
        element['snmp'][TRAPS_STR] = []
        response = cgx_session.get.snmptraps(site['id'], element['id'])
        if not response.cgx_status:
            throw_error("SNMP traps get failed: ", response)
        snmptraps = response.cgx_content['items']
        for snmptrap in snmptraps:
            snmptrap_template = copy.deepcopy(snmptrap)
            # replace flat name
            name_lookup_in_template(snmptrap_template, 'source_interface', id_name_cache)
            strip_meta_attributes(snmptrap_template)
            # no name field for this item
            element['snmp'][TRAPS_STR].append(snmptrap_template)
        delete_if_empty(element['snmp'], TRAPS_STR)

        # Get SNMP Agent
        element['snmp'][AGENT_STR] = []
        response = cgx_session.get.snmpagents(site['id'], element['id'])
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

        # Get toolkit
        response = cgx_session.get.elementaccessconfigs(element['id'])
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

        # check for duplicate names
        checked_element_name = check_name(element['name'], dup_name_dict_elements, 'Element')
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
    name_lookup_in_template(site_template, 'network_policysetstack_id', id_name_cache)
    name_lookup_in_template(site_template, 'priority_policysetstack_id', id_name_cache)
    name_lookup_in_template(site_template, 'service_binding', id_name_cache)

    strip_meta_attributes(site_template)
    # check for duplicate names
    checked_site_name = check_name(site['name'], dup_name_dict_sites, 'Site')
    # update id name cache in case name changed.
    id_name_cache[site['id']] = checked_site_name
    CONFIG[SITES_STR][checked_site_name] = site_template
    # as always, sanity check for empty site
    delete_if_empty(CONFIG[SITES_STR], checked_site_name)
    return


def pull_config_sites(sites, output_filename, passed_sdk=None, passed_report_id=None, passed_strip_versions=None,
                      passed_force_parents=None):
    """
    Main configuration pull function
    :param sites: Comma seperated list of site names or IDs, or "ALL_SITES" text.
    :param output_filename: Filename to save configuration YAML content to.
    :param passed_sdk: A cloudgenix.API() authenticated SDK object. Required if running function from external script.
    :param passed_report_id: Optional - Report ID in YAML, default False
    :param passed_strip_versions: Optional - Remove API versions from YAML, default False
    :param passed_force_parents: Optional - Leave unconfigurable parent interfaces in configuration, default False.
    :return: No return, directly writes YAML file to output_filename specified.
    """
    global ELEMENTS
    global SITES
    global CONFIG
    global REPORT_ID
    global STRIP_VERSIONS
    global FORCE_PARENTS
    global cgx_session

    # check passed vars
    if passed_sdk is not None:
        cgx_session = passed_sdk
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

    if sites is None:
        # no site specified.
        throw_error("A 'Site Name', comma-seperated list of sites 'Site A, Site B', or "
                    "'ALL_SITES' must be specified to the mandatory '--sites/-S' option.")

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
            throw_error("No matching sites found that matched entered site(s): \n"
                        "\t{0}\n"
                        "Exiting.".format("\n\t".join(sites.split(','))))

    # Got here, we got some site data.
    config_yml = open(output_filename, "w")
    config_yml.write("---\ntype: cloudgenix template\nversion: 1.0\n")
    config_yml.write("# Created at {0}\n".format(datetime.datetime.utcnow().isoformat()+"Z"))
    if cgx_session.email:
        config_yml.write("# by {0}\n".format(cgx_session.email))
    yaml.safe_dump(CONFIG, config_yml, default_flow_style=False)
    config_yml.close()

    # jd(CONFIG)
    # jd(id_name_cache)


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
    global cgx_session

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
    config_group.add_argument("--output", help="Output file name (default './config.yml')", type=str,
                              default="./config.yml")

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

    args = vars(parser.parse_args())

    REPORT_ID = args['leave_implicit_ids']
    STRIP_VERSIONS = args['strip_versions']
    FORCE_PARENTS = args['force_parents']
    filename = args['output']

    # Build SDK Constructor
    if args['controller'] and args['insecure']:
        cgx_session = cloudgenix.API(controller=args['controller'], ssl_verify=False)
    elif args['controller']:
        cgx_session = cloudgenix.API(controller=args['controller'])
    elif args['insecure']:
        cgx_session = cloudgenix.API(ssl_verify=False)
    else:
        cgx_session = cloudgenix.API()

    # check for region ignore
    if args['ignore_region']:
        cgx_session.ignore_region = True

    if args['debug']:
        cgx_session.set_debug(int(args['debug']))

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
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            throw_error("AUTH_TOKEN login failure, please check token.")

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    # pull the specified sites config
    pull_config_sites(args['sites'], filename)

    return


if __name__ == '__main__':
    go()
