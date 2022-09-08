# -*- coding: utf-8 -*-
"""
Configuration IMPORT/EXPORT common functions

**Version:** 1.7.0b3

**Author:** CloudGenix

**Copyright:** (c) 2017, 2018 CloudGenix, Inc

**License:** MIT

**Location:** <https://github.com/CloudGenix/cloudgenix_config>

#### Synopsis
Shared functions for the config pull and devops config worker scripts.

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
import copy
import sys
import re
import inspect

# CloudGenix SDK should have been checked present by other imports.
from cloudgenix import jdout, jdout_detailed

from .default_interfaces import *

# python 2 and 3 handling
if sys.version_info < (3,):
    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes


# Version for reference
__version__ = "1.7.0b3"
version = __version__

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


# regex
VERSION_REGEX = re.compile(
    r'^'                        # start of string
    r'v'                        # literal v character
    r'(?P<major>[0-9]+)'        # major number
    r'\.'                       # literal . character
    r'(?P<minor>[0-9]+)'        # minor number
    r'$'                        # end of string
)

TRAILING_INTEGER = re.compile(
    r'^'                        # start of string
    r'[a-zA-Z-]+'               # match alpha and '-' chars
    r'(?P<id>\d+)'              # match and select as group
    r'$'                        # end of string
)

# Duplicate key nag. Nag only once per run about duplicate names, don't do it each time we update n2id or id2n caches.
ALREADY_NAGGED_DUP_KEYS = []

nameable_interface_types = [
    'service_link',
    'virtual_interface'
]

skip_interface_list = [
    # 'controller 2'
]


class CloudGenixConfigError(Exception):
    """
    Custom exception for errors when not exiting.
    """
    pass


def throw_error(message, resp=None, cr=True):
    """
    Non-recoverable error, write message to STDERR and exit or raise exception
    :param message: Message text
    :param resp: Optional - CloudGenix SDK Response object
    :param cr: Optional - Use (or not) Carriage Returns.
    :return: No Return, throws exception.
    """
    output = "ERROR: " + str(message)
    if cr:
        output += "\n"
    sys.stderr.write(output)
    if resp is not None:
        output2 = str(jdout_detailed(resp))
        if cr:
            output2 += "\n"
        sys.stderr.write(output2)
    raise CloudGenixConfigError(message)


def throw_warning(message, resp=None, cr=True):
    """
    Recoverable Warning.
    :param message: Message text
    :param resp: Optional - CloudGenix SDK Response object
    :param cr: Optional - Use (or not) Carriage Returns.
    :return: None
    """
    output = "WARNING: " + str(message)
    if cr:
        output += "\n"
    sys.stderr.write(output)
    if resp is not None:
        output2 = str(jdout_detailed(resp))
        if cr:
            output2 += "\n"
        sys.stderr.write(output2)
    return


def fuzzy_pop(passed_dict, query):
    """
    Return new dict where key does not start with string.
    :param passed_dict: 1-level dict
    :param query: string
    :return: Dict without keys starting with query string.
    """
    return dict((k, v) for (k, v) in passed_dict.items() if not k.startswith(query))


def get_function_default_args(func):
    """
    Get the default values for functions.
    :param func: SDK function
    :return: Dict of args, with default values
    """
    # Python 2 and 3 handle this differently.
    if sys.version_info < (3,):
        f_args, f_varargs, f_keywords, f_defaults = inspect.getargspec(func)
    else:
        f_args, f_varargs, f_keywords, f_defaults, _, _, _ = inspect.getfullargspec(func)
    return dict(zip(reversed(f_args), reversed(f_defaults)))


def compare_versions(config_ver, sdk_ver, query):
    """
    Compare two version strings, throw error if not major match, in case of minor mismatch throw warning.
    :param config_ver: Version from config file
    :param sdk_ver: Version from SDK
    :param query: Query version came from.
    :return: SDK version for use by function.
    """
    config_dict = VERSION_REGEX.search(config_ver)
    sdk_dict = VERSION_REGEX.search(sdk_ver)
    config_major = config_dict.groupdict().get('major')
    config_minor = config_dict.groupdict().get('minor')
    sdk_major = sdk_dict.groupdict().get('major')
    sdk_minor = sdk_dict.groupdict().get('minor')
    # compare:
    if config_major == sdk_major:
        # This function is only run when there is a mismatch. If majors match, then
        # there must be a minor mismatch.
        throw_warning("{0} Config and SDK minor version mismatch: Config: {1}, SDK {2}. "
                      "".format(query, config_ver, sdk_ver))
    else:
        # major mismatch, stop.
        throw_error("{0} Config and SDK major version mismatch. Config: {1}, SDK {2}. Halting.\n"
                    "Please update config to latest SDK version".format(query, config_ver, sdk_ver))

    return sdk_ver


def config_lower_version_get(tgt_dict, query, sdk_func, default=None):
    """

    :param tgt_dict: A dict that may containin key of string and version string, EG "test v1.0"
    :param query: Text portion of string to query in dict
    :param sdk_func: CloudGenix SDK function to extract version from
    :param default: A default response to return if key does not exist.
    :return: Tuple containing:
                Value of key + version string from tgt_dict, or default value if not present.,
                API version string.
    """
    # format is "query vX.Y" where X is major and Y is minor
    args = get_function_default_args(sdk_func)
    # extract API version
    api_version = args.get('api_version')
    # if invalid API version, set to default value
    if not api_version:
        api_version = "UNDEFINED"
        throw_error("{0} API version is undefined in current SDK. Cannot configure.".format(query))
    matching_entry_list = []
    matching_entry_split = []
    for key, value in tgt_dict.items():
        # split the config entry key on space, split = None has special value (one or more spaces).
        splitkey = key.split()
        # print("DEBUG SPLIT: '{0}'".format("' '".join(splitkey)))
        # does the first half match the query?
        if splitkey[0].lower() == query:
            matching_entry_list.append(key)
            matching_entry_split.append(splitkey)
    # check match cases.
    if len(matching_entry_list) == 0:
        # no matches.
        return default, "UNDEFINED"
    # one or more matches.
    elif len(matching_entry_list) == 1:
        # check API ver content
        for idx, splitkey in enumerate(matching_entry_split):
            if len(splitkey) <= 1:
                # no api version in string.
                throw_warning("No API version in {0} config. Using latest SDK ({1})".format(query, api_version))
                retval = tgt_dict.get(matching_entry_list[idx], default)
                return default if retval is None else retval, api_version
            else:
                # check if API version string matches the current SDK config.
                if splitkey[1] == api_version:
                    # best case, exact match. go.
                    retval = tgt_dict.get(matching_entry_list[idx], default)
                    return default if retval is None else retval, api_version
                elif splitkey[1].upper() == "UNDEFINED":
                    # undefined API version, use latest.
                    throw_warning("UNDEFINED API version in {0} config. Using latest SDK ({1})"
                                  "".format(query, api_version))
                    retval = tgt_dict.get(matching_entry_list[idx], default)
                    return default if retval is None else retval, api_version
                else:
                    # no match, check if minor mismatch.
                    return_ver = compare_versions(splitkey[1], api_version, query)
                    # if we get here, minor mismatch only
                    retval = tgt_dict.get(matching_entry_list[idx], default)
                    return default if retval is None else retval, api_version
    else:
        # more than 1 config entry. Throw error.
        throw_error("Multiple configs found for {0}. Current SDK version is {1}. Please remove one of the configuration"
                    "entries to continue:".format(query, api_version), matching_entry_list)

    # if we got here, something is broken.
    return default, "UNDEFINED"


def config_lower_get(tgt_dict, query, default=None):
    """
    Case Insensitve dict get.
    :param tgt_dict: Dictionary
    :param query: String to look for key from
    :param default: Default value to return if not found.
    :return: Value in dict if found, otherwise default
    """
    value = {k.lower(): v for k, v in tgt_dict.items()}.get(query.lower(), default)
    if value is None:
        value = default
    return value


def get_default_ifconfig_from_model_string(model_string):
    """
    Return default ION Interface config when given a model string.
    :param model_string: CloudGenix Element Model String
    :return: Dict of default config.
    """
    if model_string == "ion 1000":
        return yaml.safe_load(ion_1000)
    elif model_string == "ion 1200":
        return yaml.safe_load(ion_1200)
    elif model_string == "ion 2000":
        return yaml.safe_load(ion_2000)
    elif model_string == "ion 3000":
        return yaml.safe_load(ion_3000)
    elif model_string == "ion 7000":
        return yaml.safe_load(ion_7000)
    elif model_string == "ion 9000":
        return yaml.safe_load(ion_9000)
    elif model_string == "ion 3102v":
        return yaml.safe_load(ion_3102v)
    elif model_string == "ion 3104v":
        return yaml.safe_load(ion_3104v)
    elif model_string == "ion 3108v":
        return yaml.safe_load(ion_3108v)
    elif model_string == "ion 7108v":
        return yaml.safe_load(ion_7108v)
    elif model_string == "ion 7116v":
        return yaml.safe_load(ion_7116v)
    elif model_string == "ion 7132v":
        return yaml.safe_load(ion_7132v)
    elif model_string == "ion 1200-c-row":
        return yaml.safe_load(ion_1200_c_row)
    elif model_string == "ion 1200-c-na":
        return yaml.safe_load(ion_1200_c_na)
    elif model_string == "ion 1200-c5g-ww":
        return yaml.safe_load(ion_1200_c5g_ww)
    else:
        # model not found, return empty dict
        return {}


def get_member_default_config():
    """
    Return default ION Interface config to use when being set as a bypasspair or pppoe or subif root interface.
    :return: Dict of default config.
    """
    return yaml.safe_load(member_port)


def name_lookup_in_template(template, key, lookup_dict):
    """
    Perform Name -> ID lookup for value in key. Replace with ID if found.
    :param template: Template JSON object
    :param key: Key to extract possible name from
    :param lookup_dict: Name -> ID lookup dict to use
    :return: Nothing, mutates template in-place.
    """

    cur_val = template.get(key)
    n2id_result = lookup_dict.get(cur_val)
    if n2id_result is not None:
        template[key] = n2id_result
    return


def extract_items(resp_object, error_label=None, id_key='id'):
    """
    Extract
    :param resp_object: CloudGenix Extended Requests.Response object.
    :param error_label: Optional text to describe operation on error.
    :param id_key: ID key, default 'id'
    :return: list of 'items' objects, list of IDs of objects.
    """
    items = resp_object.cgx_content.get('items')

    if resp_object.cgx_status and items is not None:
        # extract ID list
        id_list = []
        for item in items:
            item_id = item.get(id_key)
            if item_id is not None:
                id_list.append(item_id)

        # return data
        return items, id_list

    # handle 404 for certian APIs where objects may not exist
    elif resp_object.status_code in [404]:
        return [{}], []

    else:
        if error_label is not None:
            throw_error("Unable to cache {0}.".format(error_label), resp_object)
            return [], []
        else:
            throw_error("Unable to cache response.".format(error_label), resp_object)
            return [], []


def build_lookup_dict(list_content, key_val='name', value_val='id', force_nag=False, model_name=None):
    """
    Build key/value lookup dict
    :param list_content: List of dicts to derive lookup structs from
    :param key_val: value to extract from entry to be key
    :param value_val: value to extract from entry to be value
    :param force_nag: Bool, if True will nag even if key in global ALREADY_NAGGED_DUP_KEYS
    :param model_name: Element model name
    :return: lookup dict
    """
    global ALREADY_NAGGED_DUP_KEYS
    lookup_dict = {}
    blacklist_duplicate_keys = []
    blacklist_duplicate_entries = []

    for item in list_content:
        item_key = item.get(key_val)
        item_value = item.get(value_val)
        # print(item_key, item_value)
        if item_key and item_value is not None:
            # check if it's a duplicate key.
            if str(item_key) in lookup_dict:
                # First duplicate we've seen - save for warning.
                duplicate_value = lookup_dict.get(item_key)
                blacklist_duplicate_keys.append(item_key)
                blacklist_duplicate_entries.append({item_key: duplicate_value})
                blacklist_duplicate_entries.append({item_key: item_value})
                # remove from lookup dict to prevent accidental overlap usage
                #del lookup_dict[str(item_key)]

            # check if it was a third+ duplicate key for a previous key
            elif item_key in blacklist_duplicate_keys:
                # save for warning.
                blacklist_duplicate_entries.append({item_key: item_value})

            else:
                # no duplicates, append
                # Below check to handle lookup in ion 9k
                # 9k can have same port and bypasspair names
                # Adding '_bypasspair' for bypasspairs
                if key_val == 'name' and item.get('type') == 'bypasspair':
                    lookup_dict[str(item_key) + '_bypasspair'] = item_value
                # elif value_val == 'name' and item.get('type') == 'bypasspair':
                #     lookup_dict[item_key] = item_value + '_bypasspair'
                else:
                    lookup_dict[str(item_key)] = item_value

    for duplicate_key in blacklist_duplicate_keys:
        matching_entries = [entry for entry in blacklist_duplicate_entries if duplicate_key in entry]
        # check if force_nag set and if not, has key already been notified to the end user.
        if force_nag or duplicate_key not in ALREADY_NAGGED_DUP_KEYS:
            throw_warning("Lookup value '{0}' was seen two or more times. If this object is used in a config template, "
                          "it cannot be auto-referenced. To use, please remove duplicates in the controller, or "
                          "reference it explicitly by the actual value: ".format(duplicate_key), matching_entries)
            # we've now notified, add to notified list.
            ALREADY_NAGGED_DUP_KEYS.append(duplicate_key)
    return lookup_dict


def build_lookup_dict_snmp_trap(list_content):
    """
    Build key/value lookup dict specifically for SNMP Traps which use "server-ip" + "version"
    :param list_content: List of dicts to derive lookup structs from
    :return: lookup dict
    """
    lookup_dict = {}

    for item in list_content:
        item_server_ip = item.get('server_ip')
        item_version = item.get('version')
        item_id = item.get('id')

        if item_server_ip and item_version and item_id is not None:
            lookup_dict["{0}+{1}".format(item_server_ip, item_version)] = item_id

    return lookup_dict


def list_to_named_key_value(list_content, index_val='name', pop_index=True):
    """
    Build dict from list of dicts, keyed by specific value in the dicts.
    :param list_content: List of dicts to use as source
    :param index_val: Key name who's value will be used as key in returned dict
    :param pop_index: If True, delete dict key after keying.
    :return: keyed dict
    """
    keyed_dict = {}

    for item in list_content:
        item_key = item.get(index_val)

        if item_key is not None:
            if pop_index:
                value = copy.deepcopy(item)
                del value[item_key]
            else:
                value = item
            keyed_dict[item_key] = value

    return keyed_dict


def recombine_named_key_value(name_val, obj_val, name_key='name'):
    """
    Take a name-keyed dict for readability purposes and put the name back inside the dict.
    :param name_val: The value of the 'name' field
    :param obj_val: Rest of the object
    :param name_key: key label for name object.
    :return: recombined Dict.
    """
    recombined_dict = {}
    recombined_dict.update(obj_val)
    recombined_dict[name_key] = name_val

    return recombined_dict


def extract_interface_name_numerical(ifname):
    """
    Extract trailing integer from Interface name
    :param ifname: Interface name
    :return: Trailing integer or None
    """
    re_match = TRAILING_INTEGER.search(ifname)
    if re_match:
        re_extract = re_match.group('id')
        if re_extract:
            return int(re_extract)

    return None


def order_interface_by_number(interface_name_list):
    """
    Take a list of interface names, return by numerical order.
    :param interface_name_list: list of if names
    :return: sorted list of if names by trailing number
    """
    return sorted(interface_name_list, key=extract_interface_name_numerical)


def find_diff(d1, d2, path=""):
    """
    Compare two nested dictionaries.
    Derived from https://stackoverflow.com/questions/27265939/comparing-python-dictionaries-and-nested-dictionaries
    :param d1: Dict 1
    :param d2: Dict 2
    :param path: Level
    :return:
    """
    return_str = ""
    for k in d1:
        if k not in d2:
            return_str += "{0} {1}\n".format(path, ":")
            return_str += "{0} {1}\n".format(k + " as key not in d2", "\n")
        else:
            if type(d1[k]) is dict:
                if path == "":
                    path = k
                else:
                    path = path + "->" + k
                return_str += find_diff(d1[k], d2[k], path)
            elif type(d1[k]) == list:
                find_diff(dict(zip(map(str, range(len(d1[k]))), d1[k])), dict(zip(map(str, range(len(d2[k]))), d2[k])),
                          k)
            else:
                if d1[k] != d2[k]:
                    return_str += "{0} {1}\n".format(path, ":")
                    return_str += "{0} {1} {2} {3}\n".format(" - ", k, " : ", d1[k])
                    return_str += "{0} {1} {2} {3}\n".format(" + ", k, " : ", d2[k])
    return return_str


def check_name(name, dup_check_dict, function_text, error_site_txt=None):
    """
    Look up name in template, if has been used before, append count to it.
    :param name: Name to check.
    :param dup_check_dict: Dict with previously looked up values as keys, counts as items.
    :param function_text: Text to display for function in error.
    :param error_site_txt: Optional text with site name for error message.
    :return: The final name after modification.
    """

    if not name:
        # no name field, modify it to use function text + count.
        # get current count for name
        name_count = dup_check_dict.get(text_type(name), 0)
        # increment
        name_count += 1
        fixed_name = "{0} {1}".format(function_text, name_count)
        # update dup check dict
        dup_check_dict[text_type(name)] = name_count
        if not error_site_txt:
            throw_warning("No name on {0}, defaulting to '{0} {1}'".format(function_text,
                                                                           name_count))
        else:
            throw_warning("No name on {0}@{2}, defaulting to '{0} {1}'".format(function_text,
                                                                               name_count,
                                                                               error_site_txt))
        return fixed_name

    else:
        # name field exists.
        # check for duplicates
        if name in dup_check_dict.keys():
            # we have a duplicate. Handle.
            name_count = dup_check_dict.get(text_type(name), 1)
            # increment
            name_count += 1
            fixed_name = "{0} {1}".format(name, name_count)
            # update dup check dict
            dup_check_dict[text_type(name)] = name_count
            if not error_site_txt:
                throw_warning("Duplicate name {0} on a {1}, renaming to '{0} {2}'".format(name,
                                                                                          function_text,
                                                                                          name_count))
            else:
                throw_warning("Duplicate name {0} on a {1}@{3}, renaming to '{0} {2}'".format(name,
                                                                                              function_text,
                                                                                              name_count,
                                                                                              error_site_txt))
            return fixed_name

        else:
            # name is not a duplicate. Update dict for checks later.
            dup_check_dict[text_type(name)] = 1

            return name


def check_default_ipv4_config(ipv4_config):
    """
    Parse through interface ipv4_config and check if the fields are None
    :param ipv4_config: the configuration to parse
    :return: is_none = 1 if all the fields are None else 0
    """
    is_none = 1
    for k, v in ipv4_config.items():
        if k == 'type' or v in (None, 'none', 'Null', 'null'):
            continue
        elif isinstance(v, dict):
            is_none = check_default_ipv4_config(v)
        else:
            is_none = 0
    return is_none


def use_sdk_yaml_version(tgt_dict, query, sdk_func, default=None, sdk_or_yaml='sdk'):
    """
    :param tgt_dict: A dict that may containin key of string and version string, EG "test v1.0"
    :param query: Text portion of string to query in dict
    :param sdk_func: CloudGenix SDK function to extract version from
    :param default: A default response to return if key does not exist
    :param sdk_or_yaml: Input apiversion. Default is 'sdk'
    :return: default value if not present or API version string.
    """

    # format is "query vX.Y" where X is major and Y is minor
    args = get_function_default_args(sdk_func)
    # extract API version
    api_version = args.get('api_version')

    if sdk_or_yaml == 'sdk':
        # if invalid API version, set to default value
        if not api_version:
            api_version = "UNDEFINED"
            throw_error("{0} API version is undefined in current SDK. Cannot configure.".format(query))
        else:
            return api_version
    elif sdk_or_yaml == 'yaml' or sdk_or_yaml == 'yml':
        matching_entry_list = []
        matching_entry_split = []
        for key, value in tgt_dict.items():
            # split the config entry key on space, split = None has special value (one or more spaces).
            splitkey = key.split()
            # does the first half match the query?
            if splitkey[0].lower() == query:
                matching_entry_list.append(key)
                matching_entry_split.append(splitkey)
        # check match cases.
        if len(matching_entry_list) == 0:
            # no matches.
            return default, "UNDEFINED"
        # one or more matches.
        elif len(matching_entry_list) == 1:
            # check API ver content
            for idx, splitkey in enumerate(matching_entry_split):
                if len(splitkey) <= 1:
                    # no api version in string.
                    throw_error("No API version in {0} config.".format(query, api_version))
                else:
                    # check if API version string matches the current SDK config.
                    if splitkey[1] == api_version:
                        # best case, exact match. go.
                        retval = tgt_dict.get(matching_entry_list[idx], default)
                        return default if retval is None else api_version
                    elif splitkey[1].upper() == "UNDEFINED":
                        # undefined API version, use latest.
                        throw_warning("UNDEFINED API version in {0} config. Using latest SDK ({1})".format(query, api_version))
                        retval = tgt_dict.get(matching_entry_list[idx], default)
                        return default if retval is None else api_version
                    else:
                        # no match, check if minor mismatch.
                        return_ver = compare_sdk_yaml_versions(splitkey[1], api_version, query, sdk_or_yaml)
                        # if we get here, minor mismatch only
                        retval = tgt_dict.get(matching_entry_list[idx], default)
                        return default if retval is None else splitkey[1]
        else:
            # more than 1 config entry. Throw error.
            throw_error(
                "Multiple configs found for {0}. Current SDK version is {1}. Please remove one of the configuration"
                "entries to continue:".format(query, api_version), matching_entry_list)

        # if we got here, something is broken.
        return default, "UNDEFINED"


def compare_sdk_yaml_versions(config_ver, sdk_ver, query, sdk_or_yaml='sdk'):
    """
    Compare two version strings, throw error if not major match, in case of minor mismatch throw warning.
    :param config_ver: Version from config file
    :param sdk_ver: Version from SDK
    :param query: Query version came from
    :param sdk_or_yaml: Input apiversion. Default is 'sdk'
    :return: SDK version for use by function.
    """
    config_dict = VERSION_REGEX.search(config_ver)
    sdk_dict = VERSION_REGEX.search(sdk_ver)
    config_major = config_dict.groupdict().get('major')
    config_minor = config_dict.groupdict().get('minor')
    sdk_major = sdk_dict.groupdict().get('major')
    sdk_minor = sdk_dict.groupdict().get('minor')
    # compare:
    if config_major == sdk_major:
        # This function is only run when there is a mismatch. If majors match, then
        # there must be a minor mismatch.
        throw_warning("{0} Config and SDK minor version mismatch: Config: {1}, SDK {2}. "
                      "Attempting to continue, will use {3} version."
                      "".format(query, config_ver, sdk_ver, sdk_or_yaml.upper()))
    else:
        # major mismatch, stop.
        throw_error("{0} Config and SDK major version mismatch. Config: {1}, SDK {2}. Halting.\n"
                    "Please update config to latest SDK version".format(query, config_ver, sdk_ver))

    return sdk_ver if sdk_or_yaml == 'sdk' else config_ver
