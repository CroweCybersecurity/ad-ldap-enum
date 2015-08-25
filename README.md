#ldap-enume
#####Python v2.7.10

###Requirements
The package *python-ldap* is required for the script to execute. This can be installed with the following command: `pip install python-ldap`

###Usage
```
ldap_enum.py [-h] [-l LDAP_SERVER] [-d DOMAIN] [-n] [-u USERNAME] [-p PASSWORD] [-v]

AD LDAP Enumeration

optional arguments:
  -h, --help      show this help message and exit
  -v              Display Debugging Information

Server Parameters:
  -l LDAP_SERVER  LDAP Server
  -d DOMAIN       Fully Qualified Domain Name

Authentication Parameters:
  -n              Use Null Authentication
  -u USERNAME     Domain\Username
  -p PASSWORD     Password
```


###Assorted Links
* https://gist.github.com/anonymous/7451212
* http://mattfahrner.com/2014/03/09/using-paged-controls-with-python-and-ldap/
* https://social.technet.microsoft.com/Forums/windowsserver/en-US/373febac-665c-494d-91f7-834541c74bee/cant-get-all-member-objects-from-domain-users-in-ldap
* https://msdn.microsoft.com/en-us/library/Aa367017
* http://ldapwiki.willeke.com/wiki/Microsoft%20Active%20Directory%20Anomalies
