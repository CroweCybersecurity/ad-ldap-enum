#!/usr/bin/env python

from __future__ import annotations

import argparse
import asyncio
import csv
import datetime
import inspect
import ipaddress
import logging
import struct
import sys
import traceback
import warnings
from collections import defaultdict
from os.path import isfile
from time import gmtime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from msldap.commons.factory import LDAPConnectionFactory
from openpyxl import Workbook, load_workbook

# ----------------------------
# Constants / Defaults
# ----------------------------
MAX_AD_PAGE_SIZE = 1000
DEFAULT_PAGE_SIZE = MAX_AD_PAGE_SIZE
USER_CSV = 'Extended_Domain_User_Information'
GROUP_CSV = 'Domain_Group_Membership'
COMP_CSV = 'Extended_Domain_Computer_Information'

# Suppress asyncio warnings on Windows
if sys.platform == 'win32':
    warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*Event loop is closed.*")
    warnings.filterwarnings("ignore", message=".*unclosed.*", category=ResourceWarning)


# ---------- Utilities ----------

def is_ip_address(hostname: str) -> bool:
    """Return True if hostname is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def resolve_hostname_to_ip(hostname: str) -> str:
    """Resolve hostname to IP (best effort)."""
    try:
        if is_ip_address(hostname):
            return hostname
        import socket
        return socket.gethostbyname(hostname)
    except Exception as e:
        print(f'[!] Warning: Could not resolve {hostname} to IP address: {e}')
        print('[!] Using provided value as-is')
        return hostname


def parse_impacket_target(target: str) -> Tuple[str, str, Optional[str], Optional[str]]:
    """
    Parse 'domain.tld/username[:password]@OptionalHost'
    Returns (domain, username, password|None, host|None)
    """
    if not target or '/' not in target:
        raise ValueError("TARGET must be domain.tld/username[:password]@OptionalHost")

    left, host = (target, None)
    if '@' in target:
        left, host = target.rsplit('@', 1)
        host = host.strip() or None

    domain, rest = left.split('/', 1)
    if not domain or not rest:
        raise ValueError("TARGET must include domain and username")
    if ':' in rest:
        username, password = rest.split(':', 1)
    else:
        username, password = rest, None

    username = username.strip()
    domain = domain.strip()
    password = None if password is None else password
    host = host.strip() if host else None

    if not username:
        raise ValueError("Username missing in TARGET string")

    return domain, username, password, host


def get_attribute_value(attributes: Dict[str, Any], attr_name: str, default: Any = '') -> Any:
    """Safely extract attribute values from msldap response."""
    if not attributes:
        return default
    if attr_name in attributes:
        value = attributes[attr_name]
        if isinstance(value, list):
            return value[0] if value else default
        return value
    return default


def sid_to_string(sid_binary: Any) -> str:
    """Convert a binary (or string) SID to S-1-5-21-... format."""
    try:
        if sid_binary is None:
            return ''
        if isinstance(sid_binary, str):
            return sid_binary
        if not isinstance(sid_binary, (bytes, bytearray)):
            return str(sid_binary)
        if len(sid_binary) < 8:
            return f'<Invalid SID: too short ({len(sid_binary)} bytes)>'
        revision = sid_binary[0]
        sub_authority_count = sid_binary[1]
        authority = struct.unpack('>Q', b'\x00\x00' + sid_binary[2:8])[0]
        parts = [f'S-{revision}-{authority}']
        for i in range(sub_authority_count):
            start = 8 + (i * 4)
            end = start + 4
            if end <= len(sid_binary):
                sub_auth = struct.unpack('<I', sid_binary[start:end])[0]
                parts.append(str(sub_auth))
        return '-'.join(parts)
    except Exception:
        try:
            return f'<SID hex: {sid_binary.hex()}>'
        except Exception:
            return f'<SID conversion failed: {type(sid_binary)}>'


def calculate_stealth_delay(base_delay: float, jitter_percent: float = 0.0) -> float:
    """Calculate delay with optional jitter for OPSEC."""
    if jitter_percent > 0.0:
        import random
        jitter = base_delay * jitter_percent * random.uniform(-1, 1)
        return max(0.0, base_delay + jitter)
    return base_delay


def clamp_page_size(value: int) -> int:
    """Clamp requested page size to AD MaxPageSize (1..1000)."""
    try:
        return max(1, min(int(value), MAX_AD_PAGE_SIZE))
    except Exception:
        return MAX_AD_PAGE_SIZE


# ---------- Info Helpers ----------

async def get_server_info_enhanced(ldap_client) -> Dict[str, Any]:
    """Get enhanced server information using msldap built-in methods."""
    server_info: Dict[str, Any] = {}
    try:
        if hasattr(ldap_client, 'get_server_info'):
            info = await ldap_client.get_server_info()
            if info:
                server_info['server_info'] = info
                print(f'[i] Server Info: {info}')
        if hasattr(ldap_client, 'get_ad_info'):
            ad_info = await ldap_client.get_ad_info()
            if ad_info:
                server_info['ad_info'] = ad_info
                print(f'[i] Active Directory Info: {ad_info}')
        if hasattr(ldap_client, 'get_domain_name'):
            domain_name = await ldap_client.get_domain_name()
            if domain_name:
                server_info['domain_name'] = domain_name
                print(f'[i] Domain Name: {domain_name}')
    except Exception as e:
        print(f'[!] Could not retrieve server info: {e}')
        logging.warning(f'Server info retrieval failed: {e}')
    return server_info


# ---------- Models ----------

class ADUser:
    """Representation of an AD user."""

    def __init__(self, retrieved_attributes: Dict[str, Any]):
        self.distinguished_name = get_attribute_value(retrieved_attributes, 'distinguishedName')
        self.sam_account_name = get_attribute_value(retrieved_attributes, 'sAMAccountName')
        self.user_account_control = get_attribute_value(retrieved_attributes, 'userAccountControl')
        self.primary_group_id = get_attribute_value(retrieved_attributes, 'primaryGroupID')
        self.comment = str(get_attribute_value(retrieved_attributes, 'comment') or '').replace('\t', '*TAB*').replace('\r', '*CR*').replace('\n', '*LF*')
        self.description = str(get_attribute_value(retrieved_attributes, 'description') or '').replace('\t', '*TAB*').replace('\r', '*CR*').replace('\n', '*LF*')
        self.home_directory = get_attribute_value(retrieved_attributes, 'homeDirectory')
        self.display_name = get_attribute_value(retrieved_attributes, 'displayName')
        self.mail = get_attribute_value(retrieved_attributes, 'mail')
        self.password_last_set = get_attribute_value(retrieved_attributes, 'pwdLastSet')
        self.last_logon = get_attribute_value(retrieved_attributes, 'lastLogon')
        self.profile_path = get_attribute_value(retrieved_attributes, 'profilePath')
        self.locked_out = 'YES' if (get_attribute_value(retrieved_attributes, 'lockoutTime') and str(get_attribute_value(retrieved_attributes, 'lockoutTime')) != '0') else 'NO'
        self.logon_script = get_attribute_value(retrieved_attributes, 'scriptPath')
        self.user_password = get_attribute_value(retrieved_attributes, 'userPassword')
        sid_binary = get_attribute_value(retrieved_attributes, 'objectSid')
        self.object_sid = sid_to_string(sid_binary) if sid_binary else ''

    def get_account_flags(self) -> str:
        """Get account status flags from UAC."""
        output = []
        if self.user_account_control:
            uac = int(self.user_account_control)
            if uac & 2:
                output.append('DISABLED')
            if uac & 16:
                output.append('LOCKED')
            if uac & 512:
                output.append('NORMAL')
            if uac & 8388608:
                output.append('PASSWORD_EXPIRED')
            if uac & 65536:
                output.append('DONT_EXPIRE_PASSWORD')
            if uac & 262144:
                output.append('SMARTCARD_REQUIRED')
            if uac & 64:
                output.append('PASSWD_CANT_CHANGE')
        return ' '.join(output)

    def get_password_last_set_date(self) -> str:
        try:
            if self.password_last_set and int(self.password_last_set) != 0:
                val = int(self.password_last_set)
                epoch = (val / 10000000) - 11644473600
                return datetime.datetime.utcfromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            pass
        return str(self.password_last_set or '')

    def get_last_logon_date(self) -> str:
        try:
            if self.last_logon and int(self.last_logon) != 0:
                val = int(self.last_logon)
                epoch = (val / 10000000) - 11644473600
                return datetime.datetime.utcfromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            pass
        return str(self.last_logon or '')


class ADComputer:
    """Representation of an AD computer."""

    def __init__(self, retrieved_attributes: Dict[str, Any]):
        self.distinguished_name = get_attribute_value(retrieved_attributes, 'distinguishedName')
        self.sam_account_name = get_attribute_value(retrieved_attributes, 'sAMAccountName')
        self.primary_group_id = get_attribute_value(retrieved_attributes, 'primaryGroupID')
        self.operating_system = get_attribute_value(retrieved_attributes, 'operatingSystem')
        self.operating_system_hotfix = get_attribute_value(retrieved_attributes, 'operatingSystemHotfix')
        self.operating_system_service_pack = get_attribute_value(retrieved_attributes, 'operatingSystemServicePack')
        self.operating_system_version = get_attribute_value(retrieved_attributes, 'operatingSystemVersion')
        spns = get_attribute_value(retrieved_attributes, 'servicePrincipalName')
        self.service_principal_names = spns if isinstance(spns, list) else ([spns] if spns else [])
        self.last_logon = get_attribute_value(retrieved_attributes, 'lastLogon')
        self.password_last_set = get_attribute_value(retrieved_attributes, 'pwdLastSet')
        sid_binary = get_attribute_value(retrieved_attributes, 'objectSid')
        self.object_sid = sid_to_string(sid_binary) if sid_binary else ''

    def get_password_last_set_date(self) -> str:
        try:
            if self.password_last_set and int(self.password_last_set) != 0:
                val = int(self.password_last_set)
                epoch = (val / 10000000) - 11644473600
                return datetime.datetime.utcfromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            pass
        return str(self.password_last_set or '')

    def get_last_logon_date(self) -> str:
        try:
            if self.last_logon and int(self.last_logon) != 0:
                val = int(self.last_logon)
                epoch = (val / 10000000) - 11644473600
                return datetime.datetime.utcfromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            pass
        return str(self.last_logon or '')


class ADGroup:
    """Representation of an AD group."""

    def __init__(self, retrieved_attributes: Dict[str, Any]):
        self.distinguished_name = get_attribute_value(retrieved_attributes, 'distinguishedName')
        self.sam_account_name = get_attribute_value(retrieved_attributes, 'sAMAccountName')
        self.primary_group_token = get_attribute_value(retrieved_attributes, 'primaryGroupToken')
        members = get_attribute_value(retrieved_attributes, 'member')
        self.members = members if isinstance(members, list) else ([members] if members else [])
        self.is_large_group = any(k.lower().startswith('member;range') for k in retrieved_attributes.keys())


# ---------- LDAP Helpers ----------

def _get_paged_kwargs(ldap_client, base_dn: str, page_size: int, query_limit: int) -> Dict[str, Any]:
    """Build kwargs for pagedsearch tolerating msldap signature differences."""
    kwargs: Dict[str, Any] = {'tree': base_dn}
    page_size = clamp_page_size(page_size)
    try:
        sig = inspect.signature(ldap_client.pagedsearch)
        if 'page_size' in sig.parameters:
            kwargs['page_size'] = page_size
        elif 'pagesize' in sig.parameters:
            kwargs['pagesize'] = page_size
        if 'time_limit' in sig.parameters:
            kwargs['time_limit'] = query_limit
        elif 'timelimit' in sig.parameters:
            kwargs['timelimit'] = query_limit
    except Exception:
        kwargs['page_size'] = page_size
    return kwargs


async def query_ldap_with_paging(
    ldap_client,
    base_dn: str,
    search_filter_custom: str,
    attributes: List[str],
    query_limit: int,
    output_object=None,
    page_size: int = DEFAULT_PAGE_SIZE,
    delay: float = 0.0,
    jitter: float = 0.0,
) -> List[Any]:
    """Get all AD results with paging. Applies --page-size and --query_limit if supported."""
    output_list: List[Any] = []
    entry_count = 0
    kwargs = _get_paged_kwargs(ldap_client, base_dn, page_size, query_limit)

    try:
        async for entry, err in ldap_client.pagedsearch(search_filter_custom, attributes, **kwargs):
            if err is not None:
                logging.error('LDAP search error: %s - %s', type(err).__name__, err)
                continue
            if entry and 'attributes' in entry:
                entry_count += 1
                output_list.append(entry['attributes'] if output_object is None else output_object(entry['attributes']))
                if delay > 0.0:
                    await asyncio.sleep(calculate_stealth_delay(delay, jitter))
                if entry_count % 1000 == 0:
                    print(f'[i] Processed {entry_count} entries...')
    except Exception as e:
        logging.error('Critical paged search error: %s - %s', type(e).__name__, e)
        if 'authentication' in str(e).lower() or 'bind' in str(e).lower():
            raise
    return output_list


def parse_spns(service_principle_names: Iterable[str]) -> List[List[str]]:
    """Parse Service Principal Names into categorized lists (case-insensitive)."""
    def normset(seq): return {s.casefold() for s in seq}
    sql = normset(['MSSQLSvc', 'gateway', 'hbase', 'HBase', 'hdb', 'hdfs', 'hive', 'Kafka', 'mongod', 'mongos', 'MSOLAPSvc', 'MSSQL', 'oracle', 'postgres'])
    ra = normset(['vnc', 'WSMAN', 'TERMSRV', 'RPC', 'HTTP', 'https', 'jboss'])
    share = normset(['cifs', 'CIFS', 'afpserver', 'AFServer', 'nfs', 'Dfsr-12F9A27C-BF97-9364-D31B6C55EB04', 'ftp', 'iSCSITarget'])
    mail = normset(['SMTPSVC', 'SMTP', 'exchangeAB', 'exchangeMDB', 'exchangeRFR', 'IMAP', 'IMAP4', 'POP', 'POP3'])
    auth = normset(['ldap', 'aradminsvc', 'DNS', 'FIMService', 'GC', 'kadmin', 'OA60'])
    backup = normset(['AcronisAgent', 'Agent VProRecovery Norton Ghost 12.0', 'Backup Exec System Recovery Agent 6.0', 'LiveState Recovery Agent 6.0'])
    mgmt = normset(['AdtServer', 'AgpmServer', 'CAXOsoftEngine', 'CAARCserveRHAEngine', 'Cognos', 'ckp_pdp', 'CmRcService', 'Hyper-V Replica Service',
                    'Microsoft Virtual Console Service', 'MSClusterVirtualServer', 'MSServerCluster', 'MSOMHSvc', 'MSOMSdkSvc', 'PCNSCLNT', 'SCVMM'])

    buckets = [[] for _ in range(8)]
    for spn in (service_principle_names or []):
        s = str(spn)
        if s.startswith(("b'", 'b"')) and s.endswith(("'", '"')):
            s = s[2:-1]
        svc = s.split('/', 1)[0].casefold()
        if svc in sql: buckets[0].append(s)
        elif svc in ra: buckets[1].append(s)
        elif svc in share: buckets[2].append(s)
        elif svc in mail: buckets[3].append(s)
        elif svc in auth: buckets[4].append(s)
        elif svc in backup: buckets[5].append(s)
        elif svc in mgmt: buckets[6].append(s)
        else: buckets[7].append(s)
    return buckets


async def build_membership_index(ldap_client, base_dn: str, query_limit: int, page_size: int) -> Dict[str, List[str]]:
    """Single-pass scan of all objects' memberOf; invert to {group_dn: [member_dn, ...]}."""
    print('[-] Building membership index via memberOf...')
    membership: Dict[str, List[str]] = defaultdict(list)
    flt = '(|(objectCategory=user)(objectCategory=group)(objectCategory=computer))'
    attrs = ['distinguishedName', 'memberOf']
    kwargs = _get_paged_kwargs(ldap_client, base_dn, page_size, query_limit)
    count = 0
    async for entry, err in ldap_client.pagedsearch(flt, attrs, **kwargs):
        if err is not None or not entry:
            continue
        a = entry.get('attributes', {})
        dn = get_attribute_value(a, 'distinguishedName')
        if not dn:
            continue
        parents = a.get('memberOf', [])
        if isinstance(parents, str):
            parents = [parents]
        for parent in parents:
            membership[parent].append(dn)
        count += 1
        if count % 5000 == 0:
            print(f'[i] Indexed memberOf for {count} objects...')
    print(f'[i] Membership index built for {len(membership)} groups.')
    return membership


def process_group(
    users_dictionary: Dict[str, ADUser],
    groups_dictionary: Dict[str, ADGroup],
    computers_dictionary: Dict[str, ADComputer],
    group_dn: str,
    expand_nested: bool,
    base_name: Optional[str],
    seen: set,
    writer: Optional[csv.writer] = None,
) -> List[List[str]]:
    """Build group membership for a specified group; stream to CSV if writer is provided."""
    rows: List[List[str]] = []

    def emit(r: List[str]) -> None:
        if writer:
            writer.writerow(r)
        else:
            rows.append(r)

    group_name = groups_dictionary[group_dn].sam_account_name if base_name is None else base_name

    if not groups_dictionary[group_dn].members:
        emit([group_name, '', '', group_dn])

    for member in groups_dictionary[group_dn].members:
        if member in users_dictionary:
            u = users_dictionary[member]
            emit([group_name, u.sam_account_name, u.get_account_flags(), group_dn])
        elif member in computers_dictionary:
            emit([group_name, computers_dictionary[member].sam_account_name, '', group_dn])
        elif member in groups_dictionary:
            if not expand_nested or (expand_nested and base_name is None):
                emit([group_name, groups_dictionary[member].sam_account_name, '', group_dn])
            if expand_nested and member not in seen:
                seen.add(member)
                nested = process_group(
                    users_dictionary, groups_dictionary, computers_dictionary, member,
                    True, group_name, seen, writer
                )
                if not writer:
                    rows += nested
        else:
            display = member.split(',')[0].replace('CN=', '').replace('cn=', '') if 'CN=' in member.upper() else member
            emit([group_name, display, '', group_dn])

    return rows


async def ldap_queries(ldap_client, base_dn: str, expand_nested: bool, query_limit: int, args) -> None:
    """Run user/group/computer queries, stream output CSVs, and expand memberships."""
    users_dictionary: Dict[str, ADUser] = {}
    groups_dictionary: Dict[str, ADGroup] = {}
    computers_dictionary: Dict[str, ADComputer] = {}
    group_id_to_dn: Dict[str, str] = {}

    # Safe path: msldap get_all_* return async generators; use custom paged search for consistency.
    use_builtin = False
    print('[i] Using custom LDAP filters for enumeration')

    user_filter = '(objectcategory=user)'
    user_attrs = [
        'sAMAccountName', 'userAccountControl', 'primaryGroupID', 'comment',
        'description', 'homeDirectory', 'displayName', 'mail', 'pwdLastSet',
        'lastLogon', 'profilePath', 'lockoutTime', 'scriptPath',
        'userPassword', 'objectSid', 'distinguishedName'
    ]
    group_filter = '(objectcategory=group)'
    group_attrs = ['sAMAccountName', 'member', 'primaryGroupToken', 'distinguishedName']
    computer_filter = '(objectcategory=computer)'
    comp_attrs = [
        'sAMAccountName', 'primaryGroupID', 'operatingSystem',
        'operatingSystemHotfix', 'operatingSystemServicePack',
        'operatingSystemVersion', 'servicePrincipalName', 'lastLogon',
        'pwdLastSet', 'objectSid', 'distinguishedName'
    ]

    # Non-AD testing servers
    if ('forumsys.com' in str(base_dn).lower() or getattr(args, 'target_host', '') == 'ldap.forumsys.com'):
        print('[i] Detected test LDAP server, using standard LDAP filters instead of AD-specific ones')
        user_filter = '(objectclass=inetOrgPerson)'
        user_attrs = ['uid', 'cn', 'sn', 'mail', 'distinguishedName']
        group_filter = '(objectclass=groupOfUniqueNames)'
        group_attrs = ['cn', 'uniqueMember', 'distinguishedName']
        computer_filter = '(objectclass=device)'
        comp_attrs = ['cn', 'distinguishedName']
        use_builtin = False

    print('[-] Querying users...')
    try:
        users = await query_ldap_with_paging(
            ldap_client, base_dn, user_filter, user_attrs, query_limit, ADUser,
            page_size=args.page_size, delay=args.delay, jitter=args.jitter
        )
        print(f'[i] Found {len(users)} users')
    except Exception as e:
        print(f'[!] Error querying users: {e}')
        users = []

    print('[-] Querying groups...')
    try:
        groups = await query_ldap_with_paging(
            ldap_client, base_dn, group_filter, group_attrs, query_limit, ADGroup,
            page_size=args.page_size, delay=args.delay, jitter=args.jitter
        )
        print(f'[i] Found {len(groups)} groups')
    except Exception as e:
        print(f'[!] Error querying groups: {e}')
        groups = []

    print('[-] Querying computers...')
    try:
        computers = await query_ldap_with_paging(
            ldap_client, base_dn, computer_filter, comp_attrs, query_limit, ADComputer,
            page_size=args.page_size, delay=args.delay, jitter=args.jitter
        )
        print(f'[i] Found {len(computers)} computers')
    except Exception as e:
        print(f'[!] Error querying computers: {e}')
        computers = []

    # Build dictionaries
    for u in users:
        users_dictionary[u.distinguished_name] = u
    for g in groups:
        if g.primary_group_token:
            group_id_to_dn[str(g.primary_group_token)] = g.distinguished_name
        groups_dictionary[g.distinguished_name] = g
    for c in computers:
        computers_dictionary[c.distinguished_name] = c

    # Build membership index once (memberOf backlinks inverted)
    try:
        membership_index = await build_membership_index(ldap_client, base_dn, args.query_limit, args.page_size)
    except Exception as e:
        print(f'[!] Could not build membership index: {e}')
        membership_index = {}

    # For large groups, populate members via membership index (no ranged reads)
    print('[-] Resolving large groups using membership index...')
    for gdn, gobj in groups_dictionary.items():
        if gobj.is_large_group:
            gobj.members = membership_index.get(gdn, gobj.members)
    print('[-] Done resolving large groups')

    # ---------- Prepare file outputs (CSV only) ----------
    user_csv = f'{args.filename_prepend}{USER_CSV}.csv'
    comp_csv = f'{args.filename_prepend}{COMP_CSV}.csv'
    group_csv = f'{args.filename_prepend}{GROUP_CSV}.csv'

    with open(group_csv, 'w', encoding='utf-8', newline='') as f_groups:
        print(f'[-] Writing membership information to "{f_groups.name}"...')
        group_writer = csv.writer(f_groups, delimiter=',', quoting=csv.QUOTE_MINIMAL)
        group_writer.writerow(['Group Name', 'Member SAM Account Name', 'Member Status', 'Group Distinguished Name'])

        with open(user_csv, 'w', encoding='utf-8', newline='') as f_users:
            print(f'[-] Writing domain user information to "{f_users.name}"...')
            user_writer = csv.writer(f_users, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            user_writer.writerow([
                'SAM Account Name', 'Status', 'Locked Out', 'User Password',
                'Display Name', 'Email', 'Home Directory', 'Profile Path',
                'Logon Script Path', 'Password Last Set', 'Last Logon',
                'User Comment', 'Description', 'Object SID', 'Distinguished Name'
            ])

            for u in users_dictionary.values():
                gid = str(u.primary_group_id) if u.primary_group_id is not None else None
                if gid and gid in group_id_to_dn:
                    grp_dn = group_id_to_dn[gid]
                    group_writer.writerow([groups_dictionary[grp_dn].sam_account_name, u.sam_account_name, u.get_account_flags(), grp_dn])

                user_writer.writerow([
                    u.sam_account_name, u.get_account_flags(), u.locked_out, u.user_password, u.display_name,
                    u.mail, u.home_directory, u.profile_path, u.logon_script, u.get_password_last_set_date(),
                    u.get_last_logon_date(), u.comment, u.description, u.object_sid, u.distinguished_name
                ])

        with open(comp_csv, 'w', encoding='utf-8', newline='') as f_comps:
            print(f'[-] Writing domain computer information to "{f_comps.name}"...')
            comp_writer = csv.writer(f_comps, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            comp_writer.writerow([
                'SAM Account Name', 'Primary Group ID', 'OS', 'OS Hotfix',
                'OS Service Pack', 'OS Version', 'SQL SPNs', 'RA SPNS',
                'Share SPNs', 'Mail SPNs', 'Auth SPNs', 'Backup SPNs',
                'Management SPNs', 'Other SPNs', 'Last Logon', 'Password Last Set',
                'Object SID', 'Distinguished Name'
            ])

            for c in computers_dictionary.values():
                spn_buckets = parse_spns(c.service_principal_names)
                spn_cols = [','.join(map(str, b)) for b in spn_buckets]
                comp_writer.writerow([
                    c.sam_account_name, c.primary_group_id, c.operating_system, c.operating_system_hotfix,
                    c.operating_system_service_pack, c.operating_system_version, *spn_cols,
                    c.get_last_logon_date(), c.get_password_last_set_date(), c.object_sid, c.distinguished_name
                ])

                gid = str(c.primary_group_id) if c.primary_group_id is not None else None
                if gid and gid in group_id_to_dn:
                    grp_dn = group_id_to_dn[gid]
                    group_writer.writerow([groups_dictionary[grp_dn].sam_account_name, c.sam_account_name, '', grp_dn])

        print('[-] Building group membership (streamed)...')
        for idx, grp_dn in enumerate(list(groups_dictionary.keys()), 1):
            _ = process_group(users_dictionary, groups_dictionary, computers_dictionary, grp_dn, expand_nested, None, set(), group_writer)
            if idx % 1000 == 0:
                print(f'[-] Processed {idx} groups...')
        print('[-] Done')


# ---------- Main ----------

async def main():
    parser = argparse.ArgumentParser(description='Active Directory LDAP Enumerator')

    # Preferred identity: TARGET (Impacket-style)
    parser.add_argument('target', nargs='?', help='TARGET: domain.tld/username[:password]@OptionalDCFQDNOrIP')

    # Alternative identity (mutually exclusive with TARGET): DN simple bind
    parser.add_argument('-dn', '--distinguished-name', dest='distinguished_name',
                        help='Distinguished name for simple bind (mutually exclusive with TARGET)')
    parser.add_argument('-p', '--password', help='Password (used if not present in TARGET or for -dn)')

    # Auth switches (secretsdump style) — only with TARGET
    parser.add_argument('-no-pass', dest='no_pass', action='store_true',
                        help="Don't prompt for password (NTLM or Kerberos with ccache)")
    parser.add_argument('-hashes', metavar='LMHASH:NTHASH',
                        help='LM:NT hash. With -k, NT is used as RC4 key for Kerberos; else NTLM PtH.')
    parser.add_argument('-k', dest='use_kerberos', action='store_true',
                        help='Use Kerberos authentication (uses KRB5CCNAME if available; else falls back to password if provided).')
    parser.add_argument('-aesKey', dest='aes_key', metavar='HEX',
                        help='AES key for Kerberos (128 or 256 bits).')

    # Connection
    parser.add_argument('--method', choices=['ldap', 'ldaps'], default='ldap',
                        help='Connection method: ldap (389) or ldaps (636)')
    parser.add_argument('--port', type=int, help='Custom TCP port')
    parser.add_argument('--channel-binding', dest='channel_binding',
                        choices=['none', 'tls-server-end-point', 'tls-unique'],
                        default='tls-server-end-point',
                        help='Channel binding for secure connections (ldaps only)')

    # DC/host handling
    parser.add_argument('-dc-ip', dest='dc_ip', help='Domain Controller IP address (alternative to @DCFQDN in TARGET; required with -dn)')

    # Search / output
    parser.add_argument('-ql', '--query_limit', type=int, default=30, help='Search time limit in seconds')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('-x', '--excel', action='store_true', help='Output Excel file with all worksheets')
    parser.add_argument('-o', '--prepend', dest='filename_prepend', default='ad-ldap-enum_',
                        help='Prepend string to output filenames (default: ad-ldap-enum_)')

    # OPSEC
    opsec = parser.add_argument_group('OPSEC')
    opsec.add_argument('--delay', type=float, default=0.0, help='Delay in seconds between LDAP pages')
    opsec.add_argument('--jitter', type=float, default=0.0, help='Random jitter percentage (0.0-1.0)')
    opsec.add_argument('--page-size', type=int, default=DEFAULT_PAGE_SIZE,
                       help='LDAP page size (1–1000; AD MaxPageSize is 1000)')

    # Scope
    parser.add_argument('-a', '--alt-domain', dest='alt_domain',
                        help='Alternative Base DN domain (e.g., corp.local). Required with -dn.')
    parser.add_argument('-e', '--nested', dest='nested_groups', action='store_true',
                        help='Expand nested groups')

    args = parser.parse_args()

    # Enforce and warn on page-size limits (AD MaxPageSize = 1000)
    try:
        requested_ps = int(args.page_size)
    except Exception:
        requested_ps = DEFAULT_PAGE_SIZE
    if requested_ps > MAX_AD_PAGE_SIZE:
        print(f'[!] Requested --page-size {requested_ps} exceeds AD MaxPageSize {MAX_AD_PAGE_SIZE}; forcing {MAX_AD_PAGE_SIZE}.')
    elif requested_ps < 1:
        print(f'[!] Requested --page-size {requested_ps} is < 1; forcing 1.')
    args.page_size = clamp_page_size(requested_ps)

    # Identity exclusivity / requirements
    if not args.target and not args.distinguished_name:
        parser.error('TARGET is required unless using -dn.')

    if args.target and args.distinguished_name:
        parser.error('TARGET and -dn are mutually exclusive.')

    # If -dn is used, forbid auth flags and require -dc-ip, -a, and -p
    if args.distinguished_name:
        if any([args.no_pass, args.hashes, args.use_kerberos, args.aes_key]):
            parser.error('Auth flags (-no-pass, -hashes, -k, -aesKey) are not valid with -dn.')
        if not args.dc_ip:
            parser.error('-dc-ip is required with -dn (no @host accepted).')
        if not args.alt_domain:
            parser.error('-a/--alt-domain is required with -dn to form Base DN (e.g., corp.local).')
        if not args.password:
            parser.error('-p/--password is required with -dn.')

    # Prepare connection method/port
    protocol = 'ldaps' if args.method == 'ldaps' else 'ldap'
    port = args.port if args.port else (636 if args.method == 'ldaps' else 389)

    # Logging
    if args.debug:
        log_file_path = args.filename_prepend + 'Log.txt'
        print(f'[-] Writing logs to "{log_file_path}"...')
        try:
            logging.basicConfig(
                format='%(asctime)s %(levelname)-8s %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%SZ', level=logging.DEBUG,
                filename=log_file_path, filemode='a'
            )
            logging.Formatter.converter = gmtime
        except Exception as e:
            print(f'[!] Warning: Could not initialize log file: {e}')
    logging.getLogger('msldap').setLevel(logging.DEBUG if args.debug else logging.WARNING)

    # Build identity / host selection
    target_host = None
    dc_fqdn = None
    dc_ip = None
    domain = None
    username = None
    inline_password = None

    # DN simple bind path
    if args.distinguished_name:
        target_host = args.dc_ip  # required with -dn
        dc_ip = args.dc_ip
        domain = args.alt_domain  # for BaseDN only
    else:
        # TARGET path
        try:
            domain, username, inline_password, provided_host = parse_impacket_target(args.target)
        except Exception as e:
            parser.error(str(e))

        # Optional DC IP override
        if args.dc_ip:
            try:
                ipaddress.ip_address(args.dc_ip)
            except ValueError:
                parser.error('-dc-ip must be a valid IPv4/IPv6 address')
            dc_ip = args.dc_ip

        # Choose connection host: prefer @host → else -dc-ip → else domain
        target_host = provided_host or dc_ip or domain

        # Capture FQDN/IP
        if provided_host:
            if is_ip_address(provided_host):
                dc_ip = dc_ip or provided_host
            else:
                dc_fqdn = provided_host

        # If still no dc_ip, try resolving target_host
        if not dc_ip:
            dc_ip = resolve_hostname_to_ip(target_host)

    # Build BaseDN
    domain_for_basedn = args.alt_domain or domain
    if not domain_for_basedn:
        parser.error('Domain is required (TARGET domain or -a/--alt-domain).')
    base_dn = f"dc={domain_for_basedn.replace('.', ',dc=')}"
    print(f'[-] Using BaseDN of "{base_dn}"...')

    # Channel binding
    channel_binding_info = None
    if args.channel_binding != 'none' and args.method == 'ldaps':
        print(f'[i] Channel binding requested: {args.channel_binding}')
        channel_binding_info = args.channel_binding
    elif args.channel_binding != 'none' and args.method != 'ldaps':
        print('[!] Warning: Channel binding requires --method ldaps. Ignoring channel binding.')

    # Build msldap URL
    from urllib.parse import quote
    if args.distinguished_name:
        dn_enc = quote(args.distinguished_name, safe='')
        pwd_enc = quote(args.password or '', safe='')
        url = f"{protocol}+simple://{dn_enc}:{pwd_enc}@{target_host}:{port}"
    else:
        pw = inline_password or args.password
        if args.use_kerberos:
            if is_ip_address(target_host):
                print('[!] Warning: Kerberos to an IP may fail due to SPN mismatch; prefer @dc.fqdn and use -dc-ip for KDC IP.')
            if not dc_ip:
                print('[!] Could not determine DC IP; Kerberos may fail.')
            if args.aes_key:
                url = f"{protocol}+kerberos-aes://{domain}\\{username}:{quote(args.aes_key, safe='')}@{target_host}:{port}/?dc={dc_ip}"
            elif args.hashes:
                try:
                    _, nt = args.hashes.split(':', 1)
                except ValueError:
                    parser.error('-hashes must be LMHASH:NTHASH')
                url = f"{protocol}+kerberos-nt://{domain}\\{username}:{quote(nt, safe='')}@{target_host}:{port}/?dc={dc_ip}"
            elif pw:
                url = f"{protocol}+kerberos-password://{domain}\\{username}:{quote(pw, safe='')}@{target_host}:{port}/?dc={dc_ip}"
            else:
                url = f"{protocol}+kerberos-ccache://{domain}\\{username}@{target_host}:{port}/?dc={dc_ip}"
        else:
            if args.hashes:
                try:
                    _, nt = args.hashes.split(':', 1)
                except ValueError:
                    parser.error('-hashes must be LMHASH:NTHASH')
                url = f"{protocol}+ntlm-nt://{domain}\\{username}:{quote(nt, safe='')}@{target_host}:{port}"
            else:
                if pw is None:
                    if args.no_pass:
                        pw = ''
                    else:
                        parser.error('NTLM requires a password (in TARGET or -p) or -no-pass.')
                url = f"{protocol}+ntlm-password://{domain}\\{username}:{quote(pw, safe='')}@{target_host}:{port}"

    if protocol == 'ldaps' and is_ip_address(target_host):
        print('[!] LDAPS to an IP can fail certificate checks/SNI. Prefer @dc.fqdn with -dc-ip for KDC IP.')

    # Save for downstream logic
    args.target_host = target_host
    args.dc_ip_effective = dc_ip
    args.dc_fqdn_effective = dc_fqdn
    args.domain_effective = domain
    args.username_effective = username

    print(f'[-] Connecting to LDAP server at "{target_host}:{port}"...')
    if args.debug:
        print(f'[DEBUG] URL scheme selected: {url.split("://",1)[0]}://... (dc_ip={dc_ip})')

    factory = LDAPConnectionFactory.from_url(url)
    ldap_client = factory.get_client()

    if channel_binding_info:
        print('[i] Channel binding framework ready - awaiting msldap library support')

    try:
        await ldap_client.connect()
    except Exception as e:
        print(f'[e] Connection error: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)

    # Verify bind/search
    try:
        whoami = await ldap_client.whoami()
        print(f'[i] Authenticated as: {whoami}' if whoami else '[i] Authentication successful (anonymous or limited info)')
    except Exception as e:
        print(f'[!] Authentication verification failed: {e}')
    try:
        async for entry, err in ldap_client.pagedsearch('(objectClass=*)', ['objectClass'], tree=base_dn):
            if entry or err:
                break
        print('[i] LDAP search capability confirmed')
    except Exception as e:
        print(f'[!] LDAP search verification failed: {e}')
        try:
            await ldap_client.disconnect()
        finally:
            sys.exit(1)

    # Enumeration
    try:
        await ldap_queries(ldap_client, base_dn, args.nested_groups, args.query_limit, args)
    except Exception as e:
        print(f'[e] Query error: {e}')
        logging.error(traceback.format_exc())
    finally:
        try:
            await ldap_client.disconnect()
        except Exception:
            pass

    # Excel export (CSV → XLSX)
    if args.excel:
        csv_to_excel(f'{args.filename_prepend}{USER_CSV}.csv',
                     f'{args.filename_prepend}Users_Groups_Computers.xlsx', 'Users')
        csv_to_excel(f'{args.filename_prepend}{GROUP_CSV}.csv',
                     f'{args.filename_prepend}Users_Groups_Computers.xlsx', 'Groups')
        csv_to_excel(f'{args.filename_prepend}{COMP_CSV}.csv',
                     f'{args.filename_prepend}Users_Groups_Computers.xlsx', 'Computers')

    print('\n[i] Enumeration completed. Review output files for sensitive data before sharing.')


def csv_to_excel(csv_file: str, excel_file: str, sheet_name: str) -> None:
    """Convert CSV file to an Excel worksheet."""
    rows = []
    with open(csv_file, encoding='utf-8', newline='') as f:
        reader = csv.reader(f, delimiter=',')
        rows.extend(reader)
    if not isfile(excel_file):
        wb = Workbook()
        sh = wb.active
        sh.title = sheet_name
    else:
        wb = load_workbook(excel_file)
        sh = wb.create_sheet(sheet_name)
    for r in rows:
        sh.append(r)
    wb.save(excel_file)


if __name__ == '__main__':
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[!] Interrupted by user')
        sys.exit(1)
    except Exception as e:
        print(f'[!] Unexpected error: {e}')
        sys.exit(1)
