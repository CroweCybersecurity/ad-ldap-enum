# ad-ldap-enum
An LDAP based Active Directory user and group enumeration tool

### About
ad-ldap-enum is a Python script that was developed to discover users and their group memberships from Active Directory. In large Active Directory environments, tools such as NBTEnum were not performing fast enough. By executing LDAP queries against a domain controller, ad-ldap-enum is able to target specific Active Directory attributes and build out group membership quickly.

ad-ldap-enum outputs three tab delimited files 'Domain Group Membership.tsv', 'Extended Domain User Information.tsv', and 'Extended Domain Computer Information.tsv'. The first file contains users, computers, groups, and their memberships. The second file contains users and extra information about the users from Active Directory (e.g. a user's home folder or email address). The third file contains devices in the Domain Computers group and extra information about them from Active Directory (e.g. operating system type and service pack version).

ad-ldap-enum supports both authenticated and unauthenticated LDAP connections. Additionally, ad-ldap-enum can process nested groups and display a user's actual group membership.

### Requirements
The package [python-ldap](http://www.python-ldap.org/index.html) is required for the script to execute. This can be installed with the following command:
```
sudo apt-get install libsasl2-dev libldap2-dev libssl-dev
pip install python-ldap
````

Additionally, this tools has been built and tested against Python v3.8.5 and python-ldap v3.2.0

### Usage
```
ad-ldap-enum.py [-h] -l LDAP_SERVER -d DOMAIN [-a ALT_DOMAIN] [-e] [-n] [-u USERNAME] [-p PASSWORD] [-v]

Active Directory LDAP Enumerator

optional arguments:
  -h, --help                                        show this help message and exit
  -v, --verbose                                     Display debugging information.
  -o FILENAME_PREPEND, --prepend FILENAME_PREPEND   Prepend a string to all output file names.

Server Parameters:
  -l LDAP_SERVER, --server LDAP_SERVER              IP address of the LDAP server.
  -d DOMAIN, --domain DOMAIN                        Authentication account's FQDN. If an alternative domain is not specified this will be also used as the Base DN for searching LDAP.
  -a ALT_DOMAIN, --alt-domain ALT_DOMAIN            Alternative FQDN to use as the Base DN for searching LDAP.
  -e, --nested                                      Expand nested groups.

Authentication Parameters:
  -n, --null                                        Use a null binding to authenticate to LDAP.
  -s, --secure                                      Connect to LDAP over SSL
  -u USERNAME, --username USERNAME                  Authentication account's username.
  -p PASSWORD, --password PASSWORD                  Authentication account's password.
```

### Example
```python ad-ldap-enum.py -d contoso.com -l 10.0.0.1 -u Administrator -p P@ssw0rd```

### Assorted Links
* [Membership Ranges in Active Directory](https://msdn.microsoft.com/en-us/library/Aa367017)
* [Active Directory Paging](https://technet.microsoft.com/en-us/library/Cc755809(v=WS.10).aspx#w2k3tr_adsrh_how_lhjt)
