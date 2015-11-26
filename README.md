#ad-ldap-enum
#####Python v2.7.10

###Requirements
The package [python-ldap](http://www.python-ldap.org/index.html) is required for the script to execute. This can be installed with the following command:
```
pip install python-ldap
````

###Usage
```
ad-ldap-enum.py [-h] -l LDAP_SERVER -d DOMAIN [-e] [-n] [-u USERNAME]
                       [-p PASSWORD] [-v]

Active Directory LDAP Enumerator

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Display Debugging Information

Server Parameters:
  -l LDAP_SERVER, --server LDAP_SERVER
                        LDAP Server
  -d DOMAIN, --domain DOMAIN
                        Fully Qualified Domain Name
  -e, --nested          Expand Nested Groups

Authentication Parameters:
  -n, --null            Use Null Authentication
  -u USERNAME, --username USERNAME
                        Username
  -p PASSWORD, --password PASSWORD
                        Password
```


###Assorted Links
* [Membership Ranges in Active Directory](https://msdn.microsoft.com/en-us/library/Aa367017)
* [Active Directory Paging](https://technet.microsoft.com/en-us/library/Cc755809(v=WS.10).aspx#w2k3tr_adsrh_how_lhjt)
