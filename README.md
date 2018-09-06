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
    * CloudGenix Python SDK >= 5.0.1b1 - <https://github.com/CloudGenix/sdk-python>

#### License
MIT

#### Installation:
 - **PIP:** `pip install cloudgenix_config`. After install, `pull_site`/`do_site` scripts should be placed in the Python
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run `pull_site.py` and `do_site.py` scripts. 

### Examples of usage:
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
 
### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.
 - Only supports CG SDK 5.0.1b1 or greater
 - While this script can EXTRACT a single file with ALL sites, running do_sites.py on that file is NOT RECOMMENDED.
   - Best practice to do one site per config file.
   - Site safety factor is set to 1 by default (prevents unintentional multi-site configurations)
 - Re-naming Sites is not currently supported (changing site name in config causes a new site to be created)
 - Deletion of sites using `do_site.py` DESTROYS all objects under the Site. This operation is done by running `do_site.py` with the `--destroy` option.
   - Delete WILL happily auto-destroy EVERY SITE in the referenced YAML config file (Even FULLY-CONFIGURED SITES). Use with caution.
   - Site safety factor also applies to `--destroy` operations.
 - Element Extensions with specific PATH IDs are not currently templatable across multiple sites using this script.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b4** | Fix issues #8 #11 #12 and #13 |
| **1.0.0** | **b3** | More Bug fixes. |
| **1.0.0** | **b2** | Bug fixes. |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional CloudGenix Documentation at <http://support.cloudgenix.com>