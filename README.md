# ad-ldap-enum

An LDAP based Active Directory object (users, groups, and computers) enumeration tool. 

### About

ad-ldap-enum is a Python script developed to collect users/computers and their group memberships from Active Directory. In large Active Directory environments, tools such as NBTEnum were not performing fast enough. By executing LDAP queries against a domain controller, ad-ldap-enum is able to target specific Active Directory attributes and quickly build out group membership.
ad-ldap-enum outputs three tab delimited files:
- `Domain_Group_Membership.csv`
- `Extended_Domain_User_Information.csv`
- `Extended_Domain_Computer_Information.csv`

The first file contains users, computers, groups, and their memberships. The second file contains users and extra information about the users from Active Directory (e.g. a user's home folder or email address). The third file contains computers in the 'Domain Computers' group and extra information about them from Active Directory (e.g. operating system type and service pack version).
ad-ldap-enum supports both authenticated and unauthenticated LDAP connections. Additionally, ad-ldap-enum can process nested groups and display a user's actual group membership.
This tool also supports password and Pass-the-Hash (PtH) `LM:NTLM` style authentication.
ad-ldap-enum also supports LDAP over SSL/TLS connections, IPv4, and IPv6 networks.
### Requirements
The package primarily uses the [ldap3](https://ldap3.readthedocs.io/en/latest/) Python package to execute the LDAP connections and queries. To install all requirements, please run the below command:
```
python -m pip install -r 'requirements.txt'
```
Additionally, this tool has been built and tested against Python v3.10 on both Kali Linux and Windows 10. Regardless, this tool aims to be OS-agnostic working on both UNIX/Linux systems and Windows. Furthermore, Python 2.X will not be supported.
### Usage
Please see the tool's help menu below:
```
usage: ad-ldap-enum.py [-h] [-s] [-t TIMEOUT] [-ql QUERY_LIMIT]
                       [--verbosity {OFF,ERROR,BASIC,PROTOCOL,NETWORK,EXTENDED}]
                       [-lf LOG_FILE] [-p PASSWORD] [-P] [-o FILENAME_PREPEND]
                       [--legacy] [-4] [-6]
                       (-n | -u USERNAME | -dn DISTINGUISHED_NAME) -l
                       LDAP_SERVER [--port PORT] -d DOMAIN [-a ALT_DOMAIN]
                       [-e]

Active Directory LDAP Enumerator

options:
  -h, --help            show this help message and exit
  -s, --secure          Connect to LDAP over SSL/TLS
  -t TIMEOUT, --timeout TIMEOUT
                        LDAP server connection timeout in seconds
  -ql QUERY_LIMIT, --query_limit QUERY_LIMIT
                        LDAP server query timeout in seconds
  --verbosity {OFF,ERROR,BASIC,PROTOCOL,NETWORK,EXTENDED}
                        Log file LDAP verbosity level
  -lf LOG_FILE, --log_file LOG_FILE
                        Log text file path
  -p PASSWORD, --password PASSWORD
                        Authentication account's password or "LM:NTLM".
  -P, --prompt          Prompt for the authentication account's password.
  -o FILENAME_PREPEND, --prepend FILENAME_PREPEND
                        Prepend a string to all output file names' CSV.
  --legacy              Gather and output attributes using the old python-ldap
                        package .tsv format (will be deprecated)
  -4, --inet            Only use IPv4 networking (default prefer IPv4)
  -6, --inet6           Only use IPv6 networking (default prefer IPv4)
  -n, --null            Use a null binding to authenticate to LDAP.
  -u USERNAME, --username USERNAME
                        Authentication account's username.
  -dn DISTINGUISHED_NAME, --distinguished_name DISTINGUISHED_NAME
                        Authentication account's distinguished name

Server Parameters:
  -l LDAP_SERVER, --server LDAP_SERVER
                        FQDN/IP address of the LDAP server.
  --port PORT           TCP port of the LDAP server.
  -d DOMAIN, --domain DOMAIN
                        Authentication account's domain. If an alternative
                        domain is not specified, this will be also used as the
                        Base DN for searching LDAP.
  -a ALT_DOMAIN, --alt-domain ALT_DOMAIN
                        Alternative FQDN to use as the Base DN for searching
                        LDAP.
  -e, --nested          Expand nested groups.
```
### Example
Please see some examples below:

**Password authentication**
```
python 'ad-ldap-enum.py' -d contoso.com -l 10.0.0.1 -u 'Administrator' -p 'P@ssw0rd' -o 'ad-ldap-enum_2' --verbosity BASIC -lf 'ad-ldap-enum_Log.txt'
```
**Pass-the-Hash LDAPS authentication**
```
python 'ad-ldap-enum.py' -d contoso.com -l 10.0.0.1 -s -u 'Administrator' -p 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'
```

### Modification
If you would like to add more attributes to the non-legacy version, the following steps can be quickly added:
1. Find the attribute's formatted name at [All Active Directory Attributes](https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all)
   1. Please note that modifying the group output may be a little more difficult.
2. Append the attribute to the applicable object list within `user_attributes`, `group_attributes`, or `computer_attributes`
3. Update the object's class to have a default value (i.e., `distinguished_name = ''`)
4. Update the object's class to have the `__init__` function parse the retrieved attribute
5. Update the object's output section to include appending the new attribute header and value
### Planned Features
We should plan to include the following features moving forward:
- Kerberos authentication (preferably not using the Impacket suite so that the tool can be OS-agnostic)
- LDAP signing
- LDAP channel binding
- ObjectSID retrieval

Pull requests are welcome!
### Assorted Links
Please see some assorted reference links and similar projects:
- [All Active Directory Attributes](https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all)
- [Membership Ranges in Active Directory](https://msdn.microsoft.com/en-us/library/Aa367017)
- [Active Directory Paging](https://technet.microsoft.com/en-us/library/Cc755809(v=WS.10).aspx#w2k3tr_adsrh_how_lhjt)
- [LDAPDomainDumper](https://github.com/dirkjanm/ldapdomaindump)
- [ADRecon](https://github.com/adrecon/ADRecon)
- [ADSearch](https://github.com/tomcarver16/ADSearch)