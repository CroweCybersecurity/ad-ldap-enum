# ad-ldap-enum

ad-ldap-enum is a Python script developed to collect users/computers and their group membership from Active Directory. In large Active Directory environments, tools such as NBTEnum were not quick enough. By executing LDAP queries against a domain controller, ad-ldap-enum is able to target specific Active Directory attributes and quickly build out group membership.

ad-ldap-enum outputs three CSV files:

- `Domain_Group_Membership.csv`
- `Extended_Domain_User_Information.csv`
- `Extended_Domain_Computer_Information.csv`

The first file contains users, computers, groups, and their membership. The second file contains users and extra information about the users from Active Directory (e.g. a user's home folder or email address). The third file contains computers and extra information about them from Active Directory (e.g., OS type and service pack version).

## Key Features

- **Multiple Authentication Methods**: Anonymous/Null sessions, NTLM, Kerberos, and Simple Bind
- **Pass-the-Hash Support**: NTLM and Kerberos with `LM:NT` hash format
- **AES Key Support**: AES-128 (32 hex) and AES-256 (64 hex) key authentication for Kerberos
- **Credential File Support**: Direct support for .ccache and .kirbi Kerberos credential files
- **Username Format Flexibility**: Auto-detection of SAN (`DOMAIN\user`) and UPN (`user@domain.com`) formats
- **Security Identifier (SID) Support**: Retrieves and displays SIDs for users and computers
- **Secure Connections**: LDAPS (LDAP over SSL/TLS) with channel binding support
- **Channel Binding**: Enhanced security for encrypted connections (RFC 5929)
- **Nested Groups**: Process and expand nested group memberships
- **Large Group Support**: Handles Active Directory groups with thousands of members
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Excel Output**: Optional XLSX format with multiple worksheets

## Requirements

The package uses the [msldap](https://github.com/skelsec/msldap) Python package for LDAP connections and queries. To install all requirements, run:

```bash
python -m pip install -r requirements.txt
```

This tool has been built and tested with Python 3.8+ on Windows, Linux, and macOS. Python 2.x is not supported.

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

### Negotiated Kerberos/NTLM Authentication with Password

```bash
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -p 'Password123456789!'

# Using UPN format (alternative to domain\username)
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u user@domain.tld -p 'Password123456789!'
```

### Negotiated Kerberos/NTLM Authentication with Pass-the-Hash

```bash
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -p 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'

# Using UPN format
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u user@domain.tld -p 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'
```

### Kerberos Authentication

```bash
# With password
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -p 'Password123456789!' -k

# Pass-the-Hash (NT hash from LM:NT format)
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -p 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -k

# AES-128 key authentication (32 hex characters)
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -p '00000000000000000000000000000000' -k

# AES-256 key authentication (64 hex characters)
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -p '0000000000000000000000000000000000000000000000000000000000000000' -k

# Using cached credentials (Windows)
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -k

# Using Kerberos credential cache file (Linux/macOS)
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -k --ccache /path/to/krb5_cache

# Using Kerberos ticket file (.kirbi format)
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -k --kirbi /path/to/ticket.kirbi
```

### LDAPS with Channel Binding

```bash
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -p 'Password123456789!' --method ldaps --channel-binding tls-server-end-point
```

### Anonymous/Null Session

```bash
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -n
```

### Simple Bind with Distinguished Name

```bash
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -dn 'CN=user,CN=Users,DC=domain,DC=tld' -p 'Password123456789!'
```

### OPSEC (Operational Security) Examples

```bash
# Low-profile enumeration with timing controls
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -p 'Password123!' --delay 1.5 --jitter 0.3 --page-size 200

# Very stealthy enumeration with long delays and small page sizes
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -p 'Password123!' --delay 3.0 --jitter 0.5 --page-size 100

# Medium stealth with encrypted connection
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -p 'Password123!' --method ldaps --delay 1.0 --jitter 0.2 --page-size 500

# Quick enumeration with minimal delays (default behavior)
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u username123 -p 'Password123!'
```

## Parameter Reference

### Authentication Parameters

- **`-n, --null`**: Use anonymous/null authentication
- **`-u, --username`**: Username for domain authentication (supports both SAN format: `domain\user` and UPN format: `user@domain.com`)
- **`-dn, --distinguished_name`**: Full distinguished name for simple bind authentication
- **`-k, --kerberos`**: Force Kerberos authentication (requires FQDN)
- **`-p, --password`**: Password, LM:NT hash, AES-128/256 key (auto-detected)
- **`-P, --prompt`**: Prompt for password securely
- **`--ccache`**: Path to Kerberos credential cache file (.ccache format)
- **`--kirbi`**: Path to Kerberos ticket file (.kirbi format)

### Connection Parameters

- **`--method {ldap,ldaps}`**: Connection encryption (ldap=389, ldaps=636)
- **`--channel-binding`**: Security enhancement for encrypted connections
- **`-t, --timeout`**: Connection timeout in seconds (default: 10)
- **`-ql, --query_limit`**: Query timeout in seconds (default: 30)

### OPSEC Parameters

- **`--delay`**: Delay in seconds between LDAP queries (default: 0.0, recommended: 0.5-2.0 for stealth)
- **`--jitter`**: Random jitter percentage for delays (0.0-1.0, e.g., 0.3 = ±30% randomization)
- **`--page-size`**: LDAP page size for result batching (default: 1000, recommended: 100-500 for stealth)

### Server Parameters

- **`-l, --server`**: LDAP server hostname or IP address
- **`--port`**: Custom TCP port
- **`-d, --domain`**: Domain name for authentication and Base DN
- **`-a, --alt-domain`**: Alternative Base DN for searches
- **`-e, --nested`**: Expand nested group memberships
- **`-4, --inet`**: Force IPv4 only
- **`-6, --inet6`**: Force IPv6 only

### Output Parameters

- **`-x, --excel`**: Generate Excel (.xlsx) file
- **`-o, --prepend`**: Custom prefix for output filenames
- **`--legacy`**: Use legacy TSV format (fewer attributes)
- **`--debug`**: Enable detailed debug logging (shows msldap internal operations)

## Security Considerations

### FQDN vs IP Address

- **Kerberos**: Requires FQDN for proper SPN resolution
- **NTLM**: Works with both FQDN and IP addresses

### Username Formats

- **SAN Format**: `DOMAIN\username` - Traditional Windows format
- **UPN Format**: `user@domain.com` - Modern format, automatically parsed
- **Auto-Detection**: Tool automatically detects and handles both formats

### Channel Binding

- **Purpose**: Prevents SSL/TLS bypass attacks and enhances connection security
- **When to Use**: Secure environments requiring additional authentication binding

### Connection Security

- **LDAPS**: Encrypted connection over port 636 (recommended)
- **LDAP**: Unencrypted connection over port 389

### Credential File Support

- **Windows**: Uses Windows credential cache automatically when no password is provided with `-k` flag
- **Linux/macOS**: Direct support for `.ccache` files via `--ccache` parameter
- **Cross-Platform**: Direct support for `.kirbi` ticket files via `--kirbi` parameter
- **Requirements**: Credential files require `-k` (Kerberos) flag and `-u` (username) parameter

## OPSEC (Operational Security) Considerations

### Network-Level Stealth

The tool includes several parameters to help reduce detection by security monitoring systems:

#### Timing Controls

- **`--delay`**: Introduces pauses between LDAP queries to reduce network noise
  - `--delay 0.5`: Light stealth (0.5 second delays)
  - `--delay 1.0`: Medium stealth (1 second delays)  
  - `--delay 2.0`: High stealth (2 second delays)

#### Randomization

- **`--jitter`**: Adds randomness to timing to avoid predictable patterns
  - `--jitter 0.2`: ±20% randomization of delay times
  - `--jitter 0.3`: ±30% randomization (recommended)
  - `--jitter 0.5`: ±50% randomization (maximum stealth)

#### Query Optimization

- **`--page-size`**: Controls LDAP result batching to reduce large queries
  - `--page-size 100`: Very small batches (highest stealth)
  - `--page-size 200`: Small batches (high stealth)
  - `--page-size 500`: Medium batches (moderate stealth)
  - `--page-size 1000`: Default (normal operation)

### Recommended OPSEC Configurations

```bash
# High Stealth Configuration
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u user@domain.tld -p 'Password123!' --method ldaps --delay 2.0 --jitter 0.5 --page-size 100

# Medium Stealth Configuration  
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u user@domain.tld -p 'Password123!' --method ldaps --delay 1.0 --jitter 0.3 --page-size 200

# Light Stealth Configuration
python ad-ldap-enum.py -d domain.tld -l dc.domain.tld -u user@domain.tld -p 'Password123!' --delay 0.5 --jitter 0.2 --page-size 500
```

### Additional OPSEC Recommendations

1. **Use LDAPS**: Always prefer `--method ldaps` to encrypt traffic
2. **Credential Files**: Use Kerberos credential files when possible to avoid password exposure
3. **Off-Hours Operation**: Run during maintenance windows or low-activity periods
4. **Distributed Timing**: Spread enumeration across multiple sessions with significant time gaps
5. **Log Monitoring**: Be aware that LDAP queries may be logged by domain controllers

## Version History

### v2.0 - Major Update

- **New Authentication Methods**: Added full Kerberos support alongside existing NTLM
- **AES Key Support**: AES-128 (32 hex) and AES-256 (64 hex) key authentication for Kerberos
- **Advanced Kerberos**: Password, NT hash, AES-128, and AES-256 key authentication with auto-detection
- **Windows Cached Credentials**: Support for Windows Kerberos credential cache
- **Credential File Support**: Direct support for .ccache and .kirbi files via --ccache and --kirbi parameters
- **Username Format Support**: Auto-detection and handling of both SAN (`DOMAIN\user`) and UPN (`user@domain.com`) formats
- **Security Identifier (SID) Support**: Automatic retrieval and display of SIDs for users and computers
- **Enhanced Computer Attributes**: Added lastLogon and pwdLastSet timestamp support for computers
- **OPSEC Features**: Network-level operational security controls for stealth operations
  - **Timing Controls**: `--delay` parameter for introducing pauses between LDAP queries
  - **Randomization**: `--jitter` parameter for adding randomness to timing patterns
  - **Query Optimization**: `--page-size` parameter for controlling LDAP result batching
  - **Artifact Cleanup**: Automatic cleanup of temporary credential files and sensitive artifacts
- **Simplified Interface**: Automatic format detection eliminates need for authentication type flags
- **Enhanced Security**: FQDN validation for Kerberos, preventing SPN resolution issues
- **Channel Binding**: Enhanced security for encrypted connections (RFC 5929)
- **Unified Interface**: Single `-p` flag handles passwords, LM:NT hashes, and AES keys
- **Improved Reliability**: Better error handling and Windows asyncio compatibility
- **Library Migration**: Migrated from [ldap3](https://github.com/cannatag/ldap3) to [msldap](https://github.com/skelsec/msldap) for enhanced functionality

### v1.x - Legacy

- Basic NTLM authentication and anonymous connections
- Migrated from [python-ldap](https://github.com/python-ldap/python-ldap) to [ldap3](https://github.com/cannatag/ldap3)
- CSV/TSV output formats

Pull requests are welcome!

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
