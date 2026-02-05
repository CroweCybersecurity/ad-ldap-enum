# ad-ldap-enum

ad-ldap-enum is a Python script developed to collect users/computers and their group membership from Active Directory. In large Active Directory environments, tools such as NBTEnum were not quick enough. By executing LDAP queries against a domain controller, ad-ldap-enum is able to target specific Active Directory attributes and quickly build out group membership.

## Output Files

- `Domain_Group_Membership.csv`
- `Extended_Domain_User_Information.csv`
- `Extended_Domain_Computer_Information.csv`
- Optional: a single Excel workbook when `-x/--excel` is used

## Requirements

This tool has been built and tested with Python 3.10+ on Windows and Linux. It uses the [msldap](https://github.com/skelsec/msldap) Python package for LDAP connections and queries. To install the requirements, run:

```bash
python -m pip install -r requirements.txt
```

## Usage

```cmd
usage: ad-ldap-enum.py [-h] (-n | -u USERNAME | -dn DISTINGUISHED_NAME) [-k] [-p PASSWORD] [-P] [--ccache CCACHE_FILE] 
                       [--kirbi KIRBI_FILE] [--method {ldap,ldaps}] [--channel-binding {none,tls-server-end-point,tls-unique}] 
                       [-t TIMEOUT] [-ql QUERY_LIMIT] [--debug] [--legacy] 
                       [-x] [-o FILENAME_PREPEND] [--delay DELAY] [--jitter JITTER] [--page-size PAGE_SIZE] 
                       -l LDAP_SERVER [--port PORT] -d DOMAIN [-a ALT_DOMAIN] [-e] [-4] [-6]

Active Directory LDAP Enumerator

optional arguments:
  -h, --help            show this help message and exit
  -n, --null            Use anonymous/null authentication
  -u USERNAME, --username USERNAME
                        Username for authentication
  -dn DISTINGUISHED_NAME, --distinguished_name DISTINGUISHED_NAME
                        Distinguished name for simple bind authentication
  -k, --kerberos        Use Kerberos authentication
  -p PASSWORD, --password PASSWORD
                        Password, "LM:NT" hash, AES-128 key (32 hex), or AES-256 key (64 hex)
  -P, --prompt          Prompt for password
  --ccache CCACHE_FILE  Path to Kerberos credential cache file (.ccache)
  --kirbi KIRBI_FILE    Path to Kerberos ticket file (.kirbi)
  --method {ldap,ldaps}
                        Connection method: ldap (port 389) or ldaps (port 636)
  --channel-binding {none,tls-server-end-point,tls-unique}
                        Channel binding for secure connections (default: tls-server-end-point)
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout in seconds (default: 10)
  -ql QUERY_LIMIT, --query_limit QUERY_LIMIT
                        Query timeout in seconds (default: 30)
  --debug               Enable debug logging (shows detailed msldap internal operations)
  --legacy              Use legacy TSV format (fewer attributes)
  -x, --excel           Output Excel file with all worksheets
  -o FILENAME_PREPEND, --prepend FILENAME_PREPEND
                        Prepend string to output filenames (default: ad-ldap-enum_)

OPSEC Parameters:
  --delay DELAY         Delay in seconds between LDAP queries (default: 0.0)
  --jitter JITTER       Random jitter percentage for delays (0.0-1.0, e.g., 0.3 = ±30%)
  --page-size PAGE_SIZE
                        LDAP page size (default: 1000)

Server Parameters:
  -l LDAP_SERVER, --server LDAP_SERVER
                        LDAP server FQDN or IP address
  --port PORT           Custom TCP port
  -d DOMAIN, --domain DOMAIN
                        Domain name (also used as Base DN)
  -a ALT_DOMAIN, --alt-domain ALT_DOMAIN
                        Alternative Base DN for LDAP searches
  -e, --nested          Expand nested groups
  -4, --inet            Use IPv4 only
  -6, --inet6           Use IPv6 only
```

Quick examples:

```bash
# NTLM with inline password
python ad-ldap-enum.py domain.tld/username:Password123!@dc.domain.tld

# NTLM with password prompt (omit password, do not use -no-pass)
python ad-ldap-enum.py domain.tld/username@dc.domain.tld -p 'Password123!'

# Kerberos with password
python ad-ldap-enum.py domain.tld/username:Password123!@dc.domain.tld -k

# Kerberos with NT hash (LM:NT)
python ad-ldap-enum.py domain.tld/username@dc.domain.tld -k -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# LDAPS + channel binding
python ad-ldap-enum.py domain.tld/username:Password123!@dc.domain.tld --method ldaps --channel-binding tls-server-end-point
```

## Version History

### v3.0 - msldap

- **New Authentication Methods**: Added full Kerberos support alongside existing NTLM
- **AES Key Support**: AES-128 (32 hex) and AES-256 (64 hex) key authentication for Kerberos
- **Advanced Kerberos**: Password, NT hash, AES-128, and AES-256 key authentication via `-k`, `-hashes`, and `-aesKey`
- **Windows Cached Credentials**: Support for Kerberos credential cache (via KRB5CCNAME when available)
- **Security Identifier (SID) Support**: Automatic retrieval and display of SIDs for users and computers
- **Enhanced Computer Attributes**: Added lastLogon and pwdLastSet timestamp support for computers
- **OPSEC Features**: Network-level operational security controls for stealth operations
  - **Timing Controls**: `--delay` parameter for introducing pauses between LDAP queries
  - **Randomization**: `--jitter` parameter for adding randomness to timing patterns
  - **Query Optimization**: `--page-size` parameter for controlling LDAP result batching
- **Simplified Interface**: Impacket-style TARGET format for credentials and optional DC host
- **Enhanced Security**: FQDN validation for Kerberos, preventing SPN resolution issues
- **Channel Binding**: Enhanced security for encrypted connections (RFC 5929)
- **Unified Interface**: Dedicated auth flags for password, LM:NT hashes, and AES keys
- **Improved Reliability**: Better error handling and Windows asyncio compatibility
- **Library Migration**: Migrated from [ldap3](https://github.com/cannatag/ldap3) to [msldap](https://github.com/skelsec/msldap) for enhanced functionality

### v2.X - ldap3

- Migrated to [ldap3](https://github.com/cannatag/ldap3)
- Added argcomplete
- Added IPv6 support
- Expanded LDAP attributes
- Added CSV and XLSX outputs
- Added PtH and DN authentication

### v1.X - Python-LDAP

- Initial commit
- Basic NTLM authentication and anonymous connections
- Used [python-ldap](https://github.com/python-ldap/python-ldap)

## Reference Links

### Active Directory Resources

- [All Active Directory Attributes](https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all)
- [Membership Ranges in Active Directory](https://msdn.microsoft.com/en-us/library/Aa367017)
- [Active Directory Paging](https://technet.microsoft.com/en-us/library/Cc755809(v=WS.10).aspx#w2k3tr_adsrh_how_lhjt)
- [Kerberos Authentication Overview](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)

### Security and Protocol References

- [RFC 5929 - Channel Bindings for TLS](https://tools.ietf.org/html/rfc5929)
- [LDAP over SSL/TLS (LDAPS)](https://tools.ietf.org/html/rfc4513)
- [Pass-the-Hash Attack Mitigation](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers)

### Libraries and Dependencies

- [msldap - Modern LDAP client library](https://github.com/skelsec/msldap)
- [asyauth - Asynchronous authentication library](https://github.com/skelsec/asyauth)

### Similar Projects

- [LDAPDomainDumper](https://github.com/dirkjanm/ldapdomaindump)
- [ADRecon](https://github.com/adrecon/ADRecon)
- [ADSearch](https://github.com/tomcarver16/ADSearch)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [ldeep](https://github.com/franc-pentest/ldeep)
