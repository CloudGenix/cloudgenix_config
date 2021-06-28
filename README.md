
[![CloudGenix Logo](https://raw.githubusercontent.com/CloudGenix/sdk-python/master/docs/CloudGenix_Logo.png)](https://www.cloudgenix.com)

[![image](https://img.shields.io/pypi/v/cloudgenix_config.svg)](https://pypi.org/project/cloudgenix_config/)
[![image](https://img.shields.io/pypi/pyversions/cloudgenix_config.svg)](https://pypi.org/project/cloudgenix_config/)
[![Downloads](https://pepy.tech/badge/cloudgenix-config)](https://pepy.tech/project/cloudgenix-config)
[![License: MIT](https://img.shields.io/pypi/l/cloudgenix_config.svg?color=brightgreen)](https://pypi.org/project/cloudgenix_config/)
[![GitHub issues open](https://img.shields.io/github/issues/CloudGenix/cloudgenix_config.svg)](https://github.com/CloudGenix/cloudgenix_config/issues)
# CloudGenix Config (Preview)
Configuration exporting and Continuous Integration (CI) capable configuration importing for the CloudGenix Cloud Controller.

#### Synopsis
Enables export and import of configurations and templates from the CloudGenix Cloud Controller. Also, the Import of 
configuration is designed to be run on file change, to maintain configuration state on the Cloud Controller.

#### Features
 - Replace ION at site by extracting configuration, replacing 'serial_number' with new ION (Must be online and at least allocated to the account).
 - Check configurations into a repository (private GIT), and have a CI process system automatically configure site(s)
 - Use configs as a rollback tool after changes.
 - Delete most configurations by simply removing them from the file and/or setting to null.
 - Use configs as a template to deploy 10s-100s-1000s of sites.

#### Requirements
* Active CloudGenix Account
* Python >= 2.7 or >=3.6
* Python modules:
    * CloudGenix Python SDK >= 5.5.3b1 - <https://github.com/CloudGenix/sdk-python>

#### License
MIT

#### Installation:
 - **PIP:** `pip install cloudgenix_config`. After install, `pull_site`/`do_site` scripts should be placed in the Python
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run `pull_site.py` and `do_site.py` scripts.  

#### Examples of usage:
 1. Configure a Site, Element, and related objects using the UI. Record the Site name (example, MySite)
 2. Extract the configuration using the `pull_site` script: `pull_site -S "MySite" --output MySite.yaml`
    ```bash
    edwards-mbp-pro:cloudgenix_config aaron$ ./pull_site.py -S "MySite" --output MySite.yml 
    edwards-mbp-pro:cloudgenix_config aaron$ 
    ```
 3. View, edit, make changes to the configuration file as needed. Example file at <https://github.com/CloudGenix/cloudgenix_config/blob/master/example/MySite.yml>
 4. Use `do_site.py` to apply the configuration, script will get site to that state.
    ```bash
    edwards-mbp-pro:cloudgenix_config aaron$ ./do_site.py ./MySite.yml
    No Change for Site MySite.
     No Change for Waninterface Circuit to Comcast.
     No Change for Waninterface Circuit to AT&T.
     No Change for Waninterface Circuit to Megapath.
     No Change for Lannetwork NATIVE_VLAN.
     Element: Code is at correct version 5.0.1-b9.
      No Change for Element MySite Element.
       No Change for Interface 23.
       No Change for Interface 1.
       No Change for Interface controller 1.
       No Change for Interface 4.
       No Change for AS-PATH Access List test3.
       No Change for IP Community List 20.
       No Change for Routing Prefixlist test-script-list2.
       No Change for Route Map toady.
       No Change for Route Map test8.
       No Change for Route Map toady2.
       No Change for BGP Global Config 15311892501660245.
       No Change for BGP Peer teaerz.
       No Change for Staticroute 15312386843200245.
       No Change for Ntp default.
       No Change for Toolkit 15311890594020131.
    No Change for Site MySite state (active).
    DONE
    ```
 
#### CloudGenix Config Utility Upgrade Considerations:
When a major version change in the CloudGenix Config Utility is published, new parameters will likely be introduced in the YAML config template.

Please adhere to the following workflow to make sure existing configuration templates or YAML files can be reused with the latest version of the config utility:
* Step 1: Upgrade the CloudGenix Config Utility using the command ```pip install --upgrade cloudgenix_config```
* Step 2: For existing Jinja2 templates and/or site specific YAML config files, re-run ```pull_site``` for the site
* Step 3: Compare (diff) the old Jinja2 template and/or site specific YAML file with YAML file generated in Step 2.
* Step 4: Identify all the new attributes introduced in the latest version that are applicable to your configuration
* Step 5: Update the old Jinja2 template and/or YAML config file with the new parameters identified in Step 4.   

**Note**: Make sure the following steps are followed after upgrading the CloudGenix Config Utility. 
The CloudGenix Config Utility will default to using the SDK version. An out-of-date YAML file could cause issues with resource creation and/or resource updates.

#### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.
 - Requires 5.5.3b1 cloudgenix SDK. Future minor SDK revisions (5.6.x, etc.) will likely require a matching `cloudgenix_config` update.
 - While this script can EXTRACT a single file with ALL sites, running do_sites.py on that file is NOT RECOMMENDED.
   - Best practice to do one site per config file.
     - These can be automatically pulled via `pull_site.py` with `--multi-output <directory>` switch, will create a config per site.
   - Site safety factor is set to 1 by default (prevents unintentional multi-site configurations)
 - Re-naming Sites is not currently supported (changing site name in config causes a new site to be created)
 - Deletion of sites using `do_site.py` DESTROYS all objects under the Site. This operation is done by running `do_site.py` with the `--destroy` option.
   - Delete WILL happily auto-destroy EVERY SITE in the referenced YAML config file (Even FULLY-CONFIGURED SITES). Use with caution.
   - Site safety factor also applies to `--destroy` operations.
 - If Element is permanently offline or in other broken state, it will fail to be removed from a site. To force-removal, 
 use the `--declaim` option. This will unassign AND declaim (AKA "put back in inventory") the permanently offline or broken device. 
 It will also force revocation of all credentials and certificates for that device.
 - Element Extensions with specific PATH IDs are not currently templatable across multiple sites using this script.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.5.0** | **b1** | Removed mandatory 480 seconds delay (workaround for CGSDW-799) after claiming ION|
| **1.4.0** | **b5** | Default 480 second delay after claiming ION. Workaround for CGSDW-799|
|           | **b4** | Added wait-element-config parameter to introduce a delay before element configuration|
|           | **b3** | Minor bug fixes |
|           | **b2** | Minor update to requirements.txt |
|           | **b1** | Support for CloudGenix SDK 5.5.1b1, element step upgrade/downgrade|
| **1.3.0** | **b3** | Fix for issue #52|
|           | **b2** | Bug fixes|
|           | **b1** | Support for CloudGenix SDK 5.4.3b1|
| **1.2.0** | **b3** | Support for CloudGenix SDK 5.3.1b1|
|           | **b3** | Fix for Github issue #34|
|           | **b2** | Fix for Github issue #32|
|           | **b1** | Added CloudGenix SDK 5.2.1b1 support, removed SDK 5.1.1b1 support|
| **1.1.0** | **b2** | Fix for Github issues #25, #26, #27, #28, #30|
|           | **b1** | CloudGenix SDK 5.1.1b1 support|
| **1.0.0** | **b6** | PIP setup will now limit CloudGenix SDK to 5.0.3b2 for v1.0.0|
|           | **b5** | Hotfix for #16 |
|           | **b4** | Fix issues #8 #11 #12 and #13 |
|           | **b3** | More Bug fixes. |
|           | **b2** | Bug fixes. |
|           | **b1** | Initial Release. |


#### For more info
 * Get help and additional CloudGenix Documentation at <http://support.cloudgenix.com>
