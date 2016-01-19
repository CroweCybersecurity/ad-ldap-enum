#ad-ldap-enum
#####Python v2.7.10

###About
ad-ldap-enum is a Python script that was developed to discover users and their group memberships from Active Directory. In large Active Directory environments, tools such as NBTEnum were not performing fast enough. By executing LDAP queries against a domain controller, ad-ldap-enum is able to target specific Active Directory attributes and build out group membership quickly.

ad-ldap-enum outputs two tab delimited files 'Domain Group Membership.txt' and 'Extended Domain User Information.txt'. The first file contains users, computers, groups, and their memberships. The second file contains users and extra informtion about the users from Active Directory (e.g. a user's home folder or email address).

ad-ldap-enum supports both authenticated and unauthenticated LDAP connections. Additionally, ad-ldap-enum can process nested groups and display a user's actual group membership. 

###Requirements
The package [python-ldap](http://www.python-ldap.org/index.html) is required for the script to execute. This can be installed with the following command:
```
pip install python-ldap
````

###Usage
```
ad-ldap-enum.py [-h] -l LDAP_SERVER -d DOMAIN [-e] [-n] [-u USERNAME] [-p PASSWORD] [-v]

Active Directory LDAP Enumerator

optional arguments:
  -h, --help                            show this help message and exit
  -v, --verbose                         Display Debugging Information

Server Parameters:
  -l LDAP_SERVER, --server LDAP_SERVER  LDAP Server
  -d DOMAIN, --domain DOMAIN            Fully Qualified Domain Name
  -e, --nested                          Expand Nested Groups

Authentication Parameters:
  -n, --null                            Use Null Authentication
  -u USERNAME, --username USERNAME      Username
  -p PASSWORD, --password PASSWORD      Password
```


###Assorted Links
* [Membership Ranges in Active Directory](https://msdn.microsoft.com/en-us/library/Aa367017)
* [Active Directory Paging](https://technet.microsoft.com/en-us/library/Cc755809(v=WS.10).aspx#w2k3tr_adsrh_how_lhjt)
