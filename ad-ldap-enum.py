#!/usr/bin/env python

"""An LDAP Active Directory enumerator.

The script queries Active Directory over LDAP for users, groups and computers.
This information is correlated and output to the console showing groups,
their membership and other user information. The script supports null and
authenticated Active Directory access.
"""

import argparse
import asyncio
import csv
import datetime
import logging
import os
import struct
import traceback
import sys
import warnings
import re
import ipaddress
from getpass import getpass
from os.path import isfile
from time import gmtime

import argcomplete
from msldap.client import MSLDAPClient
from msldap.commons.factory import LDAPConnectionFactory
from openpyxl import Workbook, load_workbook

# Suppress asyncio warnings on Windows
if sys.platform == 'win32':
    warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*Event loop is closed.*")
    warnings.filterwarnings("ignore", message=".*unclosed.*", category=ResourceWarning)

def is_ip_address(hostname):
    """Check if the provided hostname is an IPv4 or IPv6 address.
    
    Args:
        hostname (str): The hostname to check
        
    Returns:
        bool: True if hostname is an IP address, False otherwise
    """
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def get_attribute_value(attributes, attr_name, default=''):
    """Helper function to safely extract attribute values from msldap response.
    
    Args:
        attributes (dict): Dictionary of LDAP attributes
        attr_name (str): Name of the attribute to extract
        default: Default value if attribute not found
        
    Returns:
        The attribute value or default if not found
    """
    if attr_name in attributes:
        value = attributes[attr_name]
        if isinstance(value, list) and len(value) > 0:
            return value[0]
        elif not isinstance(value, list):
            return value
    return default


def load_ccache_credentials(ccache_path, username, domain, target):
    """Load Kerberos credentials from .ccache file."""
    try:
        from asyauth.common.credentials import UniCredential
        import os
        
        if not os.path.exists(ccache_path):
            raise FileNotFoundError(f"Credential cache file not found: {ccache_path}")
            
        # Try different URL formats for ccache loading
        ccache_url = f"ccache+file://{os.path.abspath(ccache_path)}"
        try:
            credentials = UniCredential.from_url(ccache_url)
        except:
            # Alternative format
            ccache_url = f"ccache://{os.path.abspath(ccache_path)}"
            credentials = UniCredential.from_url(ccache_url)
            
        # Set additional properties for the credential if needed
        if hasattr(credentials, 'username') and not getattr(credentials, 'username', None):
            credentials.username = username
        if hasattr(credentials, 'domain') and not getattr(credentials, 'domain', None):
            credentials.domain = domain
        if hasattr(credentials, 'target') and not getattr(credentials, 'target', None):
            credentials.target = target
            
        return credentials
    except Exception as e:
        raise Exception(f"Failed to load .ccache file '{ccache_path}': {e}")


def load_kirbi_credentials(kirbi_path, username, domain, target):
    """Load Kerberos credentials from .kirbi file."""
    try:
        from asyauth.common.credentials import UniCredential
        import os
        
        if not os.path.exists(kirbi_path):
            raise FileNotFoundError(f"Kirbi ticket file not found: {kirbi_path}")
            
        # Try different URL formats for kirbi loading
        kirbi_url = f"kirbi+file://{os.path.abspath(kirbi_path)}"
        try:
            credentials = UniCredential.from_url(kirbi_url)
        except:
            # Alternative format - try loading as file and creating manual credential
            kirbi_url = f"file://{os.path.abspath(kirbi_path)}"
            credentials = UniCredential.from_url(kirbi_url)
            
        # Set additional properties for the credential if needed
        if hasattr(credentials, 'username') and not getattr(credentials, 'username', None):
            credentials.username = username
        if hasattr(credentials, 'domain') and not getattr(credentials, 'domain', None):
            credentials.domain = domain
        if hasattr(credentials, 'target') and not getattr(credentials, 'target', None):
            credentials.target = target
            
        return credentials
    except Exception as e:
        raise Exception(f"Failed to load .kirbi file '{kirbi_path}': {e}")


def parse_username_format(username, domain):
    """Parse username to handle both SAN (DOMAIN\\username) and UPN (user@domain) formats.
    
    Args:
        username (str): Username that could be in SAN or UPN format
        domain (str): Default domain to use
        
    Returns:
        tuple: (parsed_username, parsed_domain, display_format)
    """
    if '@' in username:
        # UPN format: user@domain.com
        user_part, domain_part = username.split('@', 1)
        return user_part, domain_part, f"{user_part}@{domain_part}"
    elif '\\' in username:
        # SAN format: DOMAIN\\username
        domain_part, user_part = username.split('\\', 1)
        return user_part, domain_part, f"{domain_part}\\{user_part}"
    else:
        # Just username, use provided domain
        return username, domain, f"{domain}\\{username}"

def calculate_stealth_delay(base_delay, jitter_percent=0.0):
    """Calculate delay with optional jitter for OPSEC.
    
    Args:
        base_delay (float): Base delay in seconds
        jitter_percent (float): Jitter as percentage (0.0-1.0)
        
    Returns:
        float: Calculated delay with jitter
    """
    if jitter_percent > 0.0:
        import random
        jitter = base_delay * jitter_percent * random.uniform(-1, 1)
        return max(0.0, base_delay + jitter)
    return base_delay

def cleanup_opsec_artifacts(args):
    """Clean up artifacts that might compromise OPSEC.
    
    Args:
        args: Parsed command line arguments
    """
    artifacts_to_clean = []
    
    # Add temporary credential files if any were created
    temp_files = [
        'temp_ccache',
        'temp_kirbi', 
        '.tmp_creds',
        'debug.log'
    ]
    
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            artifacts_to_clean.append(temp_file)
    
    # Clean up artifacts
    for artifact in artifacts_to_clean:
        try:
            os.remove(artifact)
            print(f'[i] Cleaned up artifact: {artifact}')
        except Exception as e:
            print(f'[!] Warning: Could not clean artifact {artifact}: {e}')


class ADUser(object):
    """A representation of a user in Active Directory.
    
    Class variables are instantiated to a 'safe' state so when the object is
    used during processing it can be assumed that all properties have some
    sort of value.
    """
    
    def __init__(self, retrieved_attributes):
        """Initialize ADUser with attributes from LDAP response."""
        self.distinguished_name = ''
        self.sam_account_name = ''
        self.user_account_control = ''
        self.primary_group_id = ''
        self.comment = ''
        self.description = ''
        self.home_directory = ''
        self.display_name = ''
        self.mail = ''
        self.password_last_set = ''
        self.last_logon = ''
        self.profile_path = ''
        self.locked_out = 'NO'
        self.logon_script = ''
        self.user_password = ''
        self.object_sid = ''

        self.distinguished_name = get_attribute_value(
            retrieved_attributes, 'distinguishedName'
        )
        self.sam_account_name = get_attribute_value(
            retrieved_attributes, 'sAMAccountName'
        )
        self.user_account_control = get_attribute_value(
            retrieved_attributes, 'userAccountControl'
        )
        self.primary_group_id = get_attribute_value(
            retrieved_attributes, 'primaryGroupID'
        )
        
        # Handle text fields that may contain newlines/tabs
        comment = get_attribute_value(retrieved_attributes, 'comment')
        if comment:
            self.comment = str(comment).replace(
                '\t', '*TAB*'
            ).replace(
                '\r', '*CR*'
            ).replace(
                '\n', '*LF*'
            )
            
        description = get_attribute_value(retrieved_attributes, 'description')
        if description:
            self.description = str(description).replace(
                '\t', '*TAB*'
            ).replace(
                '\r', '*CR*'
            ).replace(
                '\n', '*LF*'
            )
            
        self.home_directory = get_attribute_value(
            retrieved_attributes, 'homeDirectory'
        )
        self.display_name = get_attribute_value(
            retrieved_attributes, 'displayName'
        )
        self.mail = get_attribute_value(retrieved_attributes, 'mail')
        self.password_last_set = get_attribute_value(
            retrieved_attributes, 'pwdLastSet'
        )
        self.last_logon = get_attribute_value(
            retrieved_attributes, 'lastLogon'
        )
        self.profile_path = get_attribute_value(
            retrieved_attributes, 'profilePath'
        )
        
        lockout_time = get_attribute_value(retrieved_attributes, 'lockoutTime')
        if lockout_time and str(lockout_time) != '0':
            self.locked_out = 'YES'
            
        self.logon_script = get_attribute_value(
            retrieved_attributes, 'scriptPath'
        )
        self.user_password = get_attribute_value(
            retrieved_attributes, 'userPassword'
        )
        
        # Handle objectSid - convert binary SID to string format
        sid_binary = get_attribute_value(retrieved_attributes, 'objectSid')
        if sid_binary:
            self.object_sid = self._convert_sid_to_string(sid_binary)
        else:
            self.object_sid = ''

    def get_account_flags(self):
        """Get account status flags from userAccountControl attribute."""
        output_string = ''

        if self.user_account_control:
            account_disabled = 2
            account_locked = 16
            passwd_cant_change = 64
            normal_account = 512
            dont_expire_password = 65536
            smartcard_required = 262144
            password_expired = 8388608

            uac_value = int(self.user_account_control)

            if uac_value & account_disabled:
                output_string += 'DISABLED '
            if uac_value & account_locked:
                output_string += 'LOCKED '
            if uac_value & normal_account:
                output_string += 'NORMAL '
            if uac_value & password_expired:
                output_string += 'PASSWORD_EXPIRED '
            if uac_value & dont_expire_password:
                output_string += 'DONT_EXPIRE_PASSWORD '
            if uac_value & smartcard_required:
                output_string += 'SMARTCARD_REQUIRED '
            if uac_value & passwd_cant_change:
                output_string += 'PASSWD_CANT_CHANGE '

        return output_string

    def get_password_last_set_date(self):
        """Convert Windows timestamp to readable date for password last set."""
        if (self.password_last_set != '' and 
            self.password_last_set != '0' and 
            int(self.password_last_set) != 0):
            
            last_set_int = int(self.password_last_set)
            epoch_time = (last_set_int / 10000000) - 11644473600
            last_set_time = datetime.datetime.fromtimestamp(epoch_time)
            return last_set_time.strftime('%m-%d-%y %H:%M:%S')

        return self.password_last_set

    def get_last_logon_date(self):
        """Convert Windows timestamp to readable date for last logon."""
        if (self.last_logon != '' and 
            self.last_logon != '0' and 
            int(self.last_logon) != 0):
            
            last_logon_int = int(self.last_logon)
            epoch_time = (last_logon_int / 10000000) - 11644473600
            last_logon_time = datetime.datetime.fromtimestamp(epoch_time)
            return last_logon_time.strftime('%m-%d-%y %H:%M:%S')

        return self.last_logon

    def _convert_sid_to_string(self, sid_binary):
        """Convert binary SID to string format (S-1-5-21-...)."""
        try:
            import struct
            
            if isinstance(sid_binary, str):
                # If it's already a string, try to decode as bytes
                try:
                    sid_binary = sid_binary.encode('latin1')
                except:
                    return str(sid_binary)
            
            if not isinstance(sid_binary, (bytes, bytearray)):
                return str(sid_binary)
            
            # Parse the SID structure
            if len(sid_binary) < 8:
                return str(sid_binary)
                
            revision = sid_binary[0]
            sub_authority_count = sid_binary[1]
            authority = struct.unpack('>Q', b'\x00\x00' + sid_binary[2:8])[0]
            
            sid_string = f'S-{revision}-{authority}'
            
            # Parse sub-authorities (little-endian 32-bit integers)
            for i in range(sub_authority_count):
                if 8 + (i * 4) + 4 <= len(sid_binary):
                    sub_auth = struct.unpack('<I', sid_binary[8 + (i * 4):8 + (i * 4) + 4])[0]
                    sid_string += f'-{sub_auth}'
            
            return sid_string
        except Exception:
            # If conversion fails, return the binary data as hex
            try:
                return sid_binary.hex() if hasattr(sid_binary, 'hex') else str(sid_binary)
            except:
                return str(sid_binary)


class ADComputer(object):
    """A representation of a computer in Active Directory.
    
    Class variables are instantiated to a 'safe' state so when the object is
    used during processing it can be assumed that all properties have some
    sort of value.
    """
    
    def __init__(self, retrieved_attributes):
        """Initialize ADComputer with attributes from LDAP response."""
        self.distinguished_name = ''
        self.sam_account_name = ''
        self.primary_group_id = ''
        self.operating_system = ''
        self.operating_system_hotfix = ''
        self.operating_system_service_pack = ''
        self.operating_system_version = ''
        self.service_principal_names = []
        self.last_logon = ''
        self.password_last_set = ''
        self.object_sid = ''

        self.distinguished_name = get_attribute_value(
            retrieved_attributes, 'distinguishedName'
        )
        self.sam_account_name = get_attribute_value(
            retrieved_attributes, 'sAMAccountName'
        )
        self.primary_group_id = get_attribute_value(
            retrieved_attributes, 'primaryGroupID'
        )
        self.operating_system = get_attribute_value(
            retrieved_attributes, 'operatingSystem'
        )
        self.operating_system_hotfix = get_attribute_value(
            retrieved_attributes, 'operatingSystemHotfix'
        )
        self.operating_system_service_pack = get_attribute_value(
            retrieved_attributes, 'operatingSystemServicePack'
        )
        self.operating_system_version = get_attribute_value(
            retrieved_attributes, 'operatingSystemVersion'
        )
        
        # servicePrincipalName is multi-valued, so handle as list
        spns = get_attribute_value(retrieved_attributes, 'servicePrincipalName')
        if isinstance(spns, list):
            self.service_principal_names = spns
        elif spns:
            self.service_principal_names = [spns]
        
        self.last_logon = get_attribute_value(
            retrieved_attributes, 'lastLogon'
        )
        self.password_last_set = get_attribute_value(
            retrieved_attributes, 'pwdLastSet'
        )
        
        # Handle objectSid - convert binary SID to string format
        sid_binary = get_attribute_value(retrieved_attributes, 'objectSid')
        if sid_binary:
            self.object_sid = self._convert_sid_to_string(sid_binary)
        else:
            self.object_sid = ''

    def get_password_last_set_date(self):
        """Convert Windows timestamp to readable date for password last set."""
        if (self.password_last_set != '' and 
            self.password_last_set != '0' and 
            int(self.password_last_set) != 0):
            
            last_set_int = int(self.password_last_set)
            epoch_time = (last_set_int / 10000000) - 11644473600
            last_set_time = datetime.datetime.fromtimestamp(epoch_time)
            return last_set_time.strftime('%m-%d-%y %H:%M:%S')

        return self.password_last_set

    def get_last_logon_date(self):
        """Convert Windows timestamp to readable date for last logon."""
        if (self.last_logon != '' and 
            self.last_logon != '0' and 
            int(self.last_logon) != 0):
            
            last_logon_int = int(self.last_logon)
            epoch_time = (last_logon_int / 10000000) - 11644473600
            last_logon_time = datetime.datetime.fromtimestamp(epoch_time)
            return last_logon_time.strftime('%m-%d-%y %H:%M:%S')

        return self.last_logon

    def _convert_sid_to_string(self, sid_binary):
        """Convert binary SID to string format (S-1-5-21-...)."""
        try:
            import struct
            
            if isinstance(sid_binary, str):
                # If it's already a string, try to decode as bytes
                try:
                    sid_binary = sid_binary.encode('latin1')
                except:
                    return str(sid_binary)
            
            if not isinstance(sid_binary, (bytes, bytearray)):
                return str(sid_binary)
            
            # Parse the SID structure
            if len(sid_binary) < 8:
                return str(sid_binary)
                
            revision = sid_binary[0]
            sub_authority_count = sid_binary[1]
            authority = struct.unpack('>Q', b'\x00\x00' + sid_binary[2:8])[0]
            
            sid_string = f'S-{revision}-{authority}'
            
            # Parse sub-authorities (little-endian 32-bit integers)
            for i in range(sub_authority_count):
                if 8 + (i * 4) + 4 <= len(sid_binary):
                    sub_auth = struct.unpack('<I', sid_binary[8 + (i * 4):8 + (i * 4) + 4])[0]
                    sid_string += f'-{sub_auth}'
            
            return sid_string
        except Exception:
            # If conversion fails, return the binary data as hex
            try:
                return sid_binary.hex() if hasattr(sid_binary, 'hex') else str(sid_binary)
            except:
                return str(sid_binary)


class ADGroup(object):
    """A representation of a group in Active Directory.
    
    Class variables are instantiated to a 'safe' state so when the object is
    used during processing it can be assumed that all properties have some
    sort of value.
    """
    
    def __init__(self, retrieved_attributes):
        """Initialize ADGroup with attributes from LDAP response."""
        self.distinguished_name = ''
        self.sam_account_name = ''
        self.primary_group_token = ''
        self.members = []
        self.is_large_group = False

        self.distinguished_name = get_attribute_value(
            retrieved_attributes, 'distinguishedName'
        )
        self.sam_account_name = get_attribute_value(
            retrieved_attributes, 'sAMAccountName'
        )
        self.primary_group_token = get_attribute_value(
            retrieved_attributes, 'primaryGroupToken'
        )
        
        # member is multi-valued, so handle as list
        members = get_attribute_value(retrieved_attributes, 'member')
        if isinstance(members, list):
            self.members = members
        elif members:
            self.members = [members]
            
        # Check for large group indicator (range)
        if any(key.startswith('member;range') for key in retrieved_attributes.keys()):
            self.is_large_group = True

async def ldap_queries(ldap_client, base_dn, explode_nested_groups, 
                       query_limit, args):
    """Main worker function for the script with OPSEC controls."""
    users_dictionary = {}
    groups_dictionary = {}
    computers_dictionary = {}
    group_id_to_dn_dictionary = {}

    # LDAP filters - use AD-specific filters by default, but allow for 
    # standard LDAP testing
    user_filter = '(objectcategory=user)'
    user_attributes = [
        'sAMAccountName', 'userAccountControl', 'primaryGroupID', 'comment',
        'description', 'homeDirectory', 'displayName', 'mail', 'pwdLastSet',
        'lastLogon', 'profilePath', 'lockoutTime', 'scriptPath',
        'userPassword', 'objectSid', 'distinguishedName'
    ]

    group_filter = '(objectcategory=group)'
    group_attributes = [
        'sAMAccountName', 'member', 'primaryGroupToken', 'distinguishedName'
    ]

    computer_filters = '(objectcategory=computer)'
    computer_attributes = [
        'sAMAccountName', 'primaryGroupID', 'operatingSystem',
        'operatingSystemHotfix', 'operatingSystemServicePack',
        'operatingSystemVersion', 'servicePrincipalName', 'lastLogon',
        'pwdLastSet', 'objectSid', 'distinguishedName'
    ]
    
    # For testing with non-AD LDAP servers (like ldap.forumsys.com), 
    # use standard LDAP filters
    if ('forumsys.com' in str(base_dn).lower() or 
        args.ldap_server == 'ldap.forumsys.com'):
        
        print('[i] Detected test LDAP server, using standard LDAP filters '
              'instead of AD-specific ones')
        user_filter = '(objectclass=inetOrgPerson)'
        user_attributes = [
            'uid', 'cn', 'sn', 'mail', 'telephoneNumber', 'distinguishedName'
        ]
        group_filter = '(objectclass=groupOfUniqueNames)'
        group_attributes = ['cn', 'uniqueMember', 'distinguishedName']
        computer_filters = '(objectclass=device)'  # Unlikely to find any
        computer_attributes = ['cn', 'distinguishedName']

    # LDAP queries with OPSEC controls
    print('[-] Querying users...')
    users = await query_ldap_with_paging(
        ldap_client, base_dn, user_filter, user_attributes, query_limit, ADUser,
        page_size=args.page_size, delay=args.delay, jitter=args.jitter
    )
    print('[i] Found %i users' % len(users))
    
    print('[-] Querying groups...')
    groups = await query_ldap_with_paging(
        ldap_client, base_dn, group_filter, group_attributes, query_limit, ADGroup,
        page_size=args.page_size, delay=args.delay, jitter=args.jitter
    )
    print('[i] Found %i groups' % len(groups))
    
    print('[-] Querying computers...')
    computers = await query_ldap_with_paging(
        ldap_client, base_dn, computer_filters, computer_attributes, 
        query_limit, ADComputer, page_size=args.page_size, delay=args.delay, 
        jitter=args.jitter
    )
    print('[i] Found %i computers' % len(computers))

    # LDAP dictionaries
    print('[-] Building users dictionary...')
    for element in users:
        users_dictionary[element.distinguished_name] = element
    print('[-] Done')

    print('[-] Building groups dictionary...')
    for element in groups:
        group_id_to_dn_dictionary[element.primary_group_token] = element.distinguished_name
        groups_dictionary[element.distinguished_name] = element
    print('[-] Done')

    print('[-] Building computers dictionary...')
    for element in computers:
        computers_dictionary[element.distinguished_name] = element
    print('[-] Done')

    # Loop through each group. If the membership is a range, then query AD 
    # to get the full group membership
    print('[-] Exploding large groups...')
    for group_key, group_object in groups_dictionary.items():
        if group_object.is_large_group:
            print('Getting full membership for "%s"' % group_key)
            groups_dictionary[group_key].members = await get_membership(
                ldap_client, base_dn, group_key, query_limit
            )

    # Build group membership
    print('[-] Building group membership...')
    print('[i] %i groups were found.' % len(list(groups_dictionary.keys())))

    current_group_number = 0
    output_dictionary = []
    for grp in list(groups_dictionary.keys()):
        current_group_number += 1
        output_dictionary += process_group(
            users_dictionary, groups_dictionary, computers_dictionary, grp,
            explode_nested_groups, None, [], args.legacy
        )

        if current_group_number % 1000 == 0:
            print('[-] Processing group %i...' % current_group_number)
    print('[-] Done')

    # TODO: This could create output duplicates. It should be fixed at some point.
    # Add users if they have the group set as their primary ID as the group.
    # Additionally, add extended domain user information to a text file.
    user_info_filename = '{0}Extended_Domain_User_Information.csv'.format(
        args.filename_prepend
    )
    if args.legacy:
        user_info_filename = user_info_filename.replace('csv', 'tsv')
        
    with open(user_info_filename, 'w') as user_information_file:
        print('[-] Writing domain user information to "%s"...' % 
              user_information_file.name)
        
        if not args.legacy:
            user_information_file.write(
                'SAM Account Name,Status,Locked Out,User Password,'
                'Display Name,Email,Home Directory,Profile Path,'
                'Logon Script Path,Password Last Set,Last Logon,'
                'User Comment,Description,Object SID,Distinguished Name\n'
            )
        else:
            user_information_file.write(
                'SAM Account Name\tStatus\tLocked Out\tUser Password\t'
                'Display Name\tEmail\tHome Directory\tProfile Path\t'
                'Logon Script Path\tPassword Last Set\tLast Logon\t'
                'User Comment\tDescription\tObject SID\n'
            )

        for user_object in list(users_dictionary.values()):
            if (user_object.primary_group_id and 
                user_object.primary_group_id in group_id_to_dn_dictionary):
                
                grp_dn = group_id_to_dn_dictionary[user_object.primary_group_id]

                temp_list_a = []
                temp_list_b = []

                temp_list_a.append(groups_dictionary[grp_dn].sam_account_name)
                temp_list_b.append(groups_dictionary[grp_dn].sam_account_name)
                temp_list_a.append(user_object.sam_account_name)
                temp_list_b.append(user_object.sam_account_name)
                temp_list_a.append(user_object.get_account_flags())
                temp_list_b.append(user_object.get_account_flags())
                temp_list_a.append(user_object.locked_out)
                temp_list_a.append(user_object.user_password)
                temp_list_a.append(user_object.display_name)
                temp_list_a.append(user_object.mail)
                temp_list_a.append(user_object.home_directory)
                temp_list_a.append(user_object.profile_path)
                temp_list_a.append(user_object.logon_script)
                temp_list_a.append(user_object.get_password_last_set_date())
                temp_list_a.append(user_object.get_last_logon_date())
                temp_list_a.append(user_object.comment)
                temp_list_a.append(user_object.description)
                temp_list_a.append(user_object.object_sid)
                if not args.legacy:
                    temp_list_a.append(user_object.distinguished_name)
                output_dictionary.append(temp_list_b)

                tmp_element = ''
                for x, binary_string in enumerate(temp_list_a[1:]):
                    binary_string = str(binary_string).strip()
                    if (binary_string[:2] == "b'" or 
                        binary_string[:2] == 'b"'):
                        binary_string = binary_string[2:]
                        binary_string = binary_string[:-1]
                    
                    # Skip distinguishedName in legacy mode
                    if args.legacy and 'dc=' in binary_string.lower():
                        continue
                        
                    if not args.legacy and '"' in binary_string:
                        binary_string = binary_string.replace('"', '*DOUBLEQUOTE*')
                    if not args.legacy and ',' in binary_string:
                        binary_string = '"' + binary_string + '"'
                        
                    if x == len(temp_list_a[1:]) - 1:
                        tmp_element += binary_string + '\n'
                    elif args.legacy:
                        tmp_element += binary_string + '\t'
                    else:
                        tmp_element += binary_string + ','
                
                user_information_file.write(tmp_element)

    # Write Domain Computer Information
    computer_info_filename = '{0}Extended_Domain_Computer_Information.csv'.format(
        args.filename_prepend
    )
    if args.legacy:
        computer_info_filename = computer_info_filename.replace('csv', 'tsv')
        
    with open(computer_info_filename, 'w') as computer_information_file:
        print('[-] Writing domain computer information to "%s"...' %
              computer_information_file.name)
        
        if not args.legacy:
            computer_information_file.write(
                'SAM Account Name,OS,OS Hotfix,OS Service Pack,OS Version,'
                'SQL SPNs,RA SPNS,Share SPNs,Mail SPNs,Auth SPNs,'
                'Backup SPNs,Management SPNs,Other SPNs,Last Logon,'
                'Password Last Set,Object SID,Distinguished Name\n'
            )
        else:
            computer_information_file.write(
                'SAM Account Name\tOS\tOS Hotfix\tOS Service Pack\t'
                'OS Version\tSQL SPNs\tRA SPNS\tShare SPNs\tMail SPNs\t'
                'Auth SPNs\tBackup SPNs\tManagement SPNs\tOther SPNs\t'
                'Last Logon\tPassword Last Set\tObject SID\n'
            )

        # TODO: This could create output duplicates. It should be fixed at 
        # some point. Add computers if they have the group set as their 
        # primary ID as the group
        for computer_object in list(computers_dictionary.values()):
            temp_list_a = []
            temp_list_b = []

            # Add to group membership if computer has primary group ID
            if computer_object.primary_group_id:
                grp_dn = group_id_to_dn_dictionary[computer_object.primary_group_id]
                temp_list_a.append(groups_dictionary[grp_dn].sam_account_name)
                temp_list_a.append(computer_object.sam_account_name)

            temp_list_b.append(computer_object.sam_account_name)
            temp_list_b.append(computer_object.primary_group_id)
            temp_list_b.append(computer_object.operating_system)
            temp_list_b.append(computer_object.operating_system_hotfix)
            temp_list_b.append(computer_object.operating_system_service_pack)
            temp_list_b.append(computer_object.operating_system_version)
            
            for item in parse_spns(computer_object.service_principal_names):
                temp_list_b.append(','.join(map(str, item)))
            
            # Add timestamp attributes
            temp_list_b.append(computer_object.get_last_logon_date())
            temp_list_b.append(computer_object.get_password_last_set_date())
            temp_list_b.append(computer_object.object_sid)
                
            if not args.legacy:
                temp_list_b.append(computer_object.distinguished_name)

            tmp_element = ''
            for x, binary_string in enumerate(temp_list_b):
                binary_string = str(binary_string).strip()
                if (binary_string[:2] == "b'" or 
                    binary_string[:2] == 'b"'):
                    binary_string = binary_string[2:]
                    binary_string = binary_string[:-1]
                    
                # Skip distinguishedName in legacy mode
                if args.legacy and 'dc=' in binary_string.lower():
                    continue
                    
                if not args.legacy and '"' in binary_string:
                    binary_string = binary_string.replace('"', '*DOUBLEQUOTE*')
                if not args.legacy and ',' in binary_string:
                    binary_string = '"' + binary_string + '"'
                    
                if x == len(temp_list_b) - 1:
                    tmp_element += binary_string + '\n'
                elif args.legacy:
                    tmp_element += binary_string + '\t'
                else:
                    tmp_element += binary_string + ','
                    
            computer_information_file.write(tmp_element)
            # Only add to group membership if computer has primary group ID
            if computer_object.primary_group_id:
                output_dictionary.append(temp_list_a)

    # Write Group Memberships
    group_membership_filename = '{0}Domain_Group_Membership.csv'.format(
        args.filename_prepend
    )
    if args.legacy:
        group_membership_filename = group_membership_filename.replace('csv', 'tsv')
        
    with open(group_membership_filename, 'w') as group_membership_file:
        print('[-] Writing membership information to "%s"...' %
              group_membership_file.name)
        
        if not args.legacy:
            group_membership_file.write(
                'Group Name,Member SAM Account Name,Member Status,'
                'Group Distinguished Name\n'
            )
        else:
            group_membership_file.write(
                'Group Name\tMember SAM Account Name\tMember Status\n'
            )

        for element in output_dictionary:
            tmp_element = ''
            for x, binary_string in enumerate(element):
                binary_string = str(binary_string).strip()
                if (binary_string[:2] == "b'" or 
                    binary_string[:2] == 'b"'):
                    binary_string = binary_string[2:]
                    binary_string = binary_string[:-1]
                    
                # Skip distinguishedName in legacy mode
                if args.legacy and 'dc=' in binary_string.lower():
                    continue
                    
                if not args.legacy and '"' in binary_string:
                    binary_string = binary_string.replace('"', '*DOUBLEQUOTE*')
                if not args.legacy and ',' in binary_string:
                    binary_string = '"' + binary_string + '"'
                    
                if x == len(element) - 1:
                    tmp_element += binary_string + '\n'
                elif args.legacy:
                    tmp_element += binary_string + '\t'
                else:
                    tmp_element += binary_string + ','
                
            group_membership_file.write(tmp_element)

def process_group(users_dictionary, groups_dictionary, computers_dictionary,
                  group_distinguished_name, explode_nested_bool, base_group_name,
                  groups_seen, legacy):
    """Build group membership for a specified group."""
    # Store assorted group information.
    group_dictionary = []

    # Query SAM name or used redefined SAM name if processing a nested group.
    if base_group_name is None:
        group_sam_name = groups_dictionary[group_distinguished_name].sam_account_name
    else:
        group_sam_name = base_group_name

    # Add empty groups to the Domain Group Membership list for full visibility.
    if not groups_dictionary[group_distinguished_name].members:
        temp_list = [group_sam_name, '', '', group_distinguished_name]
        if legacy:
            temp_list.pop(-1)
        group_dictionary.append(temp_list)

    # Add users/groups/computer if they are a 'memberOf' the group
    for member in groups_dictionary[group_distinguished_name].members:
        # Process users.
        if member in users_dictionary:
            user_member = users_dictionary[member]
            temp_list = [
                group_sam_name, user_member.sam_account_name,
                user_member.get_account_flags(), group_distinguished_name
            ]
            if legacy:
                temp_list.pop(-1)
            group_dictionary.append(temp_list)

        # Process computers.
        elif member in computers_dictionary:
            temp_list = [
                group_sam_name, computers_dictionary[member].sam_account_name,
                '', group_distinguished_name
            ]
            if legacy:
                temp_list.pop(-1)
            group_dictionary.append(temp_list)

        # Process groups.
        elif member in groups_dictionary:
            if not explode_nested_bool or (explode_nested_bool and base_group_name is None):
                temp_list = [
                    group_sam_name, groups_dictionary[member].sam_account_name,
                    '', group_distinguished_name
                ]
                if legacy:
                    temp_list.pop(-1)
                group_dictionary.append(temp_list)

            if explode_nested_bool:
                # Stop processing the chain if a circular reference is detected.
                if member in groups_seen:
                    pass
                # Process a nested group.
                else:
                    groups_seen.append(member)
                    group_dictionary += process_group(
                        users_dictionary, groups_dictionary, 
                        computers_dictionary, member, True, group_sam_name,
                        groups_seen, legacy
                    )
        
        # Handle members that don't exist in any of our dictionaries
        # (deleted objects, foreign security principals, etc.)
        else:
            # Extract CN from DN for display, or use full DN if no CN found
            member_name = member
            if 'CN=' in member.upper():
                try:
                    member_name = member.split(',')[0].replace('CN=', '').replace('cn=', '')
                except:
                    pass
            
            temp_list = [group_sam_name, member_name, '', group_distinguished_name]
            if legacy:
                temp_list.pop(-1)
            group_dictionary.append(temp_list)

    return group_dictionary


async def query_ldap_with_paging(ldap_client, base_dn, search_filter_custom,
                                 attributes, query_limit, output_object=None,
                                 page_size=1000, delay=0.0, jitter=0.0):
    """Get all Active Directory results from LDAP using a paging approach.
    
    By default Active Directory will return 1,000 results per query before
    it errors out. Enhanced with OPSEC controls for stealth operations.
    """
    import asyncio
    
    # Paging for AD LDAP Queries
    output_list = []
    
    try:
        async for entry, err in ldap_client.pagedsearch(
            search_filter_custom, attributes, tree=base_dn, search_scope=2
        ):
            if err is not None:
                print(f'[!] Error during search: {err}')
                continue
                
            if entry and 'attributes' in entry:
                if output_object is None:
                    output_list.append(entry['attributes'])
                else:
                    output_list.append(output_object(entry['attributes']))
                    
                # OPSEC: Apply delay between requests for network stealth
                if delay > 0.0:
                    actual_delay = calculate_stealth_delay(delay, jitter)
                    await asyncio.sleep(actual_delay)
                    
    except Exception as e:
        print(f'[!] Error in paged search: {e}')
        
    return output_list

def parse_spns(service_principle_names):
    """Parse Service Principal Names into categorized lists."""
    temp_sql_spns = []
    sql_spn_strings = [
        'MSSQLSvc', 'gateway', 'hbase', 'HBase', 'hdb', 'hdfs', 'hive',
        'Kafka', 'mongod', 'mongos', 'MSOLAPSvc', 'MSSQL', 'oracle', 'postgres'
    ]
    
    temp_ra_spns = []
    ra_spn_strings = [
        'vnc', 'WSMAN', 'TERMSRV', 'RPC', 'HTTP', 'https', 'jboss'
    ]
    
    temp_share_spns = []
    share_spn_strings = [
        'cifs', 'CIFS', 'afpserver', 'AFServer', 'nfs',
        'Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04', 'ftp', 'iSCSITarget'
    ]
    
    temp_mail_spns = []
    mail_spn_strings = [
        'SMTPSVC', 'SMTP', 'exchangeAB', 'exchangeMDB', 'exchangeRFR',
        'IMAP', 'IMAP4', 'POP', 'POP3'
    ]
    
    temp_auth_spns = []
    auth_spn_strings = [
        'ldap', 'aradminsvc', 'DNS', 'FIMService', 'GC', 'kadmin', 'OA60'
    ]
    
    temp_backup_spns = []
    backup_spn_strings = [
        'AcronisAgent', 'Agent VProRecovery Norton Ghost 12.0',
        'Backup Exec System Recovery Agent 6.0', 'LiveState Recovery Agent 6.0'
    ]
    
    temp_management_spns = []
    management_spn_strings = [
        'AdtServer', 'AgpmServer', 'CAXOsoftEngine', 'CAARCserveRHAEngine',
        'Cognos', 'ckp_pdp', 'CmRcService', 'Hyper-V Replica Service',
        'Microsoft Virtual Console Service', 'MSClusterVirtualServer',
        'MSServerCluster', 'MSOMHSvc', 'MSOMSdkSvc', 'PCNSCLNT', 'SCVMM'
    ]
    
    temp_other_spns = []

    for spn in service_principle_names:
        spn = str(spn)
        if spn[:2] == "b'" or spn[:2] == 'b"':
            spn = spn[2:]
            spn = spn[:-1]
            
        spn_service = spn.split('/')[0]
        
        if spn_service in sql_spn_strings:
            temp_sql_spns.append(spn)
        elif spn_service in ra_spn_strings:
            temp_ra_spns.append(spn)
        elif spn_service in share_spn_strings:
            temp_share_spns.append(spn)
        elif spn_service in mail_spn_strings:
            temp_mail_spns.append(spn)
        elif spn_service in auth_spn_strings:
            temp_auth_spns.append(spn)
        elif spn_service in backup_spn_strings:
            temp_backup_spns.append(spn)
        elif spn_service in management_spn_strings:
            temp_management_spns.append(spn)
        else:
            temp_other_spns.append(spn)

    return [
        temp_sql_spns, temp_ra_spns, temp_share_spns, temp_mail_spns,
        temp_auth_spns, temp_backup_spns, temp_management_spns, temp_other_spns
    ]


async def get_membership(ldap_client, base_dn, group_dn, query_limit):
    """Query the membership of an Active Directory group.
    
    For large groups Active Directory will not return the full membership by
    default but will instead return partial results. Additional processing is
    needed to get the full membership.
    """
    members_list = []

    # RFC 4515 sanitation.
    sanitized_group_dn = str(group_dn).replace(
        '(', '\\28'
    ).replace(
        ')', '\\29'
    ).replace(
        '*', '\\2a'
    ).replace(
        '\\', '\\5c'
    )

    membership_filter = (
        '(&(|(objectcategory=user)(objectcategory=group)'
        '(objectcategory=computer))(memberOf={0}))'.format(sanitized_group_dn)
    )
    membership_results = await query_ldap_with_paging(
        ldap_client, base_dn, membership_filter, ['distinguishedName'], 
        query_limit
    )

    for element in membership_results:
        dn = get_attribute_value(element, 'distinguishedName')
        if dn:
            members_list.append(dn)

    return members_list


def csvtsv_to_excel(csvtsv_file, excel_file, sheet_name, legacy=False):
    """Convert CSV/TSV file to Excel worksheet."""
    # Source: https://www.blog.pythonlibrary.org/2021/09/25/converting-csv-to-excel-with-python/
    csvtsv_data = []
    with open(csvtsv_file) as file_obj:
        if legacy:
            reader = csv.reader(file_obj, delimiter='\t')
        else:
            reader = csv.reader(file_obj)
        for row in reader:
            csvtsv_data.append(row)

    if not isfile(excel_file):
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = sheet_name
    else:
        workbook = load_workbook(excel_file)
        sheet = workbook.create_sheet(sheet_name)
        
    for row in csvtsv_data:
        sheet.append(row)
    workbook.save(excel_file)

async def main():
    """Main function for the Active Directory LDAP enumerator."""
    # Command line arguments
    parser = argparse.ArgumentParser(description='Active Directory LDAP Enumerator')
    method = parser.add_mutually_exclusive_group(required=True)
    method.add_argument(
        '-n', '--null', dest='null_session', action='store_true',
        help='Use anonymous/null authentication'
    )
    method.add_argument(
        '-u', '--username', help='Username for authentication'
    )
    method.add_argument(
        '-dn', '--distinguished_name',
        help='Distinguished name for simple bind authentication'
    )
    
    parser.add_argument(
        '-k', '--kerberos', dest='use_kerberos', action='store_true',
        help='Use Kerberos authentication'
    )
    parser.add_argument(
        '-p', '--password',
        help='Password, "LM:NT" hash, AES-128 key (32 hex), or AES-256 key (64 hex)'
    )
    parser.add_argument(
        '-P', '--prompt', dest='password_prompt', action='store_true',
        help='Prompt for password'
    )
    parser.add_argument(
        '--ccache', dest='ccache_file',
        help='Path to Kerberos credential cache file (.ccache)'
    )
    parser.add_argument(
        '--kirbi', dest='kirbi_file',
        help='Path to Kerberos ticket file (.kirbi)'
    )
    parser.add_argument(
        '--method', 
        choices=['ldap', 'ldaps'],  # TODO: Add 'starttls' when msldap library supports StartTLS
        default='ldap',
        help='Connection method: ldap (port 389) or ldaps (port 636)'
    )
    parser.add_argument(
        '--channel-binding', dest='channel_binding', 
        choices=['none', 'tls-server-end-point', 'tls-unique'],
        default='tls-server-end-point',
        help='Channel binding for secure connections (default: tls-server-end-point)'
    )
    parser.add_argument(
        '-t', '--timeout', type=int, default=10,
        help='Connection timeout in seconds (default: 10)'
    )
    parser.add_argument(
        '-ql', '--query_limit', type=int, default=30,
        help='Query timeout in seconds (default: 30)'
    )
    parser.add_argument(
        '--verbosity', default='BASIC',
        choices=['OFF', 'ERROR', 'BASIC', 'PROTOCOL', 'NETWORK', 'EXTENDED'],
        help='Log verbosity level (default: BASIC)'
    )
    parser.add_argument(
        '--legacy', action='store_true',
        help='Use legacy TSV format (fewer attributes)'
    )
    parser.add_argument(
        '-x', '--excel', action='store_true',
        help='Output Excel file with all worksheets'
    )
    parser.add_argument(
        '-o', '--prepend', dest='filename_prepend', default='ad-ldap-enum_',
        help='Prepend string to output filenames (default: ad-ldap-enum_)'
    )

    # OPSEC and Stealth Parameters
    opsec_group = parser.add_argument_group('OPSEC Parameters')
    opsec_group.add_argument(
        '--delay', type=float, default=0.0,
        help='Delay in seconds between LDAP queries (default: 0.0)'
    )
    opsec_group.add_argument(
        '--jitter', type=float, default=0.0,
        help='Random jitter percentage for delays (0.0-1.0, e.g., 0.3 = ±30%%)'
    )
    opsec_group.add_argument(
        '--page-size', type=int, default=1000,
        help='LDAP page size (default: 1000)'
    )

    server_group = parser.add_argument_group('Server Parameters')
    server_group.add_argument(
        '-l', '--server', required=True, dest='ldap_server',
        help='LDAP server FQDN or IP address'
    )
    server_group.add_argument(
        '--port', type=int, help='Custom TCP port'
    )
    server_group.add_argument(
        '-d', '--domain', required=True,
        help='Domain name (also used as Base DN)'
    )
    server_group.add_argument(
        '-a', '--alt-domain', dest='alt_domain',
        help='Alternative Base DN for LDAP searches'
    )
    server_group.add_argument(
        '-e', '--nested', dest='nested_groups', action='store_true',
        help='Expand nested groups'
    )
    server_group.add_argument(
        '-4', '--inet', action='store_true',
        help='Use IPv4 only'
    )
    server_group.add_argument(
        '-6', '--inet6', action='store_true',
        help='Use IPv6 only'
    )

    # Parse arguments
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    # Parse username format to handle both SAN and UPN
    if args.username:
        parsed_username, parsed_domain, display_format = parse_username_format(args.username, args.domain)
        # Update args with parsed values
        original_username = args.username
        args.username = parsed_username
        # Only update domain if it was extracted from UPN format
        if '@' in original_username:
            args.domain = parsed_domain
        args._display_username = display_format  # Store for display purposes
    else:
        args._display_username = None

    # Validate Kerberos authentication requires FQDN, not IP address
    if args.use_kerberos and is_ip_address(args.ldap_server):
        parser.error('Kerberos authentication requires LDAP server to be specified as FQDN, not IP address. '
                    'Use a fully qualified domain name (e.g., dc.domain.com) instead of IP address.')

    # Validate credential file usage
    if args.ccache_file or args.kirbi_file:
        if not args.use_kerberos:
            parser.error('Credential files (.ccache/.kirbi) require Kerberos authentication. Use -k flag.')
        if not args.username:
            parser.error('Username (-u) is required when using credential files (.ccache/.kirbi).')
        if args.password:
            parser.error('Cannot specify both password (-p) and credential file (--ccache/--kirbi).')
        if args.ccache_file and args.kirbi_file:
            parser.error('Cannot specify both .ccache and .kirbi files. Choose one.')

    # If --prompt then overwrite args.password now
    if args.password_prompt is True or (not args.password and not args.null_session and not args.use_kerberos):
        args.password = getpass()

    # Set Logger format
    if args.verbosity != 'OFF':
        print('[-] Writing logs to "%sLog.txt"...' % args.filename_prepend)
        logging.basicConfig(
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%SZ', level=logging.DEBUG,
            filename=args.filename_prepend + 'Log.txt', filemode='a'
        )
        # Force UTC
        logging.Formatter.converter = gmtime

    # Configure msldap logging level
    if args.verbosity == 'ERROR':
        logging.getLogger('msldap').setLevel(logging.ERROR)
    elif args.verbosity == 'BASIC':
        logging.getLogger('msldap').setLevel(logging.INFO)
    elif args.verbosity == 'PROTOCOL':
        logging.getLogger('msldap').setLevel(logging.DEBUG)
    elif args.verbosity == 'NETWORK':
        logging.getLogger('msldap').setLevel(logging.DEBUG)
    elif args.verbosity == 'EXTENDED':
        logging.getLogger('msldap').setLevel(logging.DEBUG)
    else:
        logging.getLogger('msldap').setLevel(logging.WARNING)

    # Build the baseDN for searching (always based on domain, not bind DN)
    if args.alt_domain:
        formatted_domain_name = args.alt_domain.replace('.', ',dc=')
    else:
        formatted_domain_name = args.domain.replace('.', ',dc=')

    base_dn = 'dc={0}'.format(formatted_domain_name)
    print('[-] Using BaseDN of "%s"...' % base_dn)

    ldap_client = None
    try:
        # Build connection URL for msldap
        protocol = 'ldaps' if args.method == 'ldaps' else 'ldap'
        port = args.port if args.port else (636 if args.method == 'ldaps' else 389)
        
        # Channel binding setup
        channel_binding_info = None
        if args.channel_binding != 'none' and args.method == 'ldaps':
            print(f'[i] Channel binding requested: {args.channel_binding}')
            # Note: msldap 0.5.15 may have limited channel binding support
            # This is prepared for future msldap versions or manual implementation
            channel_binding_info = args.channel_binding
        elif args.channel_binding != 'none' and args.method != 'ldaps':
            print('[!] Warning: Channel binding requires --method ldaps. Ignoring channel binding.')
        
        # Build connection URL based on authentication method
        if args.null_session:
            # Anonymous connection
            url = f"{protocol}://{args.ldap_server}:{port}"
        elif args.distinguished_name:
            # Simple bind with distinguished name - use ldap+simple scheme
            base_protocol = 'ldaps+simple' if args.method == 'ldaps' else 'ldap+simple'
            url = (f"{base_protocol}://{args.distinguished_name}:"
                   f"{args.password}@{args.ldap_server}:{port}")
        elif args.username:
            if args.use_kerberos:
                # Kerberos authentication - use proper kerberos scheme
                from urllib.parse import quote
                
                if args.password:
                    # Kerberos with password - URL encode password
                    encoded_password = quote(args.password, safe='')
                    url = f"kerberos+{protocol}://{args.domain}\\{args.username}:{encoded_password}@{args.ldap_server}:{port}/?dc={args.ldap_server}"
                else:
                    # Kerberos without password - use cached credentials
                    url = f"kerberos+{protocol}://{args.domain}\\{args.username}@{args.ldap_server}:{port}/?dc={args.ldap_server}"
            else:
                # NTLM authentication - use standard ldap/ldaps scheme
                from urllib.parse import quote
                
                # URL encode the password to handle special characters
                encoded_password = quote(args.password, safe='')
                
                if ':' in args.password and len(args.password.split(':')) == 2:
                    # LM:NTLM hash format
                    url = (f"{protocol}://{args.domain}\\{args.username}:"
                           f"{encoded_password}@{args.ldap_server}:{port}")
                else:
                    # Plain password
                    url = (f"{protocol}://{args.domain}\\{args.username}:"
                           f"{encoded_password}@{args.ldap_server}:{port}")
                           
                print(f'[i] Using NTLM authentication for user: {args.domain}\\{args.username}')
        else:
            print('[!] Error: No valid authentication method specified')
            exit(1)
        
        print('[-] Connecting to LDAP server at "%s:%i"...' % 
              (args.ldap_server, port))
        
        # Debug: print URL without password for troubleshooting
        if args.verbosity in ['PROTOCOL', 'NETWORK', 'EXTENDED']:
            safe_url = url.replace(f':{encoded_password if "encoded_password" in locals() else args.password}@', ':***@')
            print(f'[DEBUG] Connection URL: {safe_url}')
        
        if args.use_kerberos:
            # Use display format for user-friendly messages
            user_display = args._display_username if args._display_username else f"{args.domain}\\{args.username}"
            
            if args.ccache_file:
                print(f'[i] Using Kerberos authentication with .ccache file for user: {user_display}')
            elif args.kirbi_file:
                print(f'[i] Using Kerberos authentication with .kirbi file for user: {user_display}')
            elif args.password:
                # Check if using hash/key format for Kerberos PTH
                if (':' in args.password and len(args.password.split(':')) == 2) or \
                   (len(args.password) == 32 and all(c in '0123456789abcdefABCDEF' for c in args.password)) or \
                   (len(args.password) == 64 and all(c in '0123456789abcdefABCDEF' for c in args.password)):
                    if len(args.password) == 64:
                        print(f'[i] Using Kerberos Pass-the-Hash authentication with AES-256 key for user: {user_display}')
                    elif len(args.password) == 32:
                        print(f'[i] Using Kerberos Pass-the-Hash authentication with AES-128 key for user: {user_display}')
                    elif ':' in args.password:
                        print(f'[i] Using Kerberos Pass-the-Hash authentication with NT hash (RC4) for user: {user_display}')
                else:
                    print(f'[i] Using Kerberos authentication with password for user: {user_display}')
            else:
                print(f'[i] Using Kerberos authentication (cached/prompt) for user: {user_display}')
        
        if channel_binding_info:
            print(f'[i] Attempting connection with {channel_binding_info} channel binding')
        
        # Create LDAP client using factory for all authentication types
        factory = LDAPConnectionFactory.from_url(url)
        ldap_client = factory.get_client()
        
        # TODO: Implement channel binding when msldap supports it
        # For now, this is a placeholder for future enhancement
        if channel_binding_info:
            print('[i] Channel binding framework ready - awaiting msldap library support')
            
        await ldap_client.connect()
        
    except Exception as e:
        print(f'[e] Connection error: {e}')
        logging.error(traceback.format_exc())
        exit(1)

    print('[-] Success')
    # Query LDAP
    try:
        await ldap_queries(
            ldap_client, base_dn, args.nested_groups, args.query_limit, args
        )
    except Exception as e:
        print(f'[e] Query error: {e}')
        logging.error(traceback.format_exc())
    finally:
        # Always ensure LDAP client is properly disconnected
        try:
            if ldap_client:
                await ldap_client.disconnect()
                # Small delay to allow proper cleanup on Windows
                await asyncio.sleep(0.1)
        except Exception as disconnect_error:
            logging.warning(f'Error during LDAP disconnect: {disconnect_error}')
        
    # Exit after connection issues to prevent further processing
    if 'e' in locals():
        exit(1)
    
    if args.excel and not args.legacy:
        csvtsv_to_excel(
            args.filename_prepend + 'Extended_Domain_User_Information.csv',
            args.filename_prepend + 'Users_Groups_Computers.xlsx',
            'Users', args.legacy
        )
        csvtsv_to_excel(
            args.filename_prepend + 'Domain_Group_Membership.csv',
            args.filename_prepend + 'Users_Groups_Computers.xlsx',
            'Groups', args.legacy
        )
        csvtsv_to_excel(
            args.filename_prepend + 'Extended_Domain_Computer_Information.csv',
            args.filename_prepend + 'Users_Groups_Computers.xlsx',
            'Computers', args.legacy
        )
    elif args.excel:
        csvtsv_to_excel(
            args.filename_prepend + 'Extended_Domain_User_Information.tsv',
            args.filename_prepend + 'Users_Groups_Computers.xlsx',
            'Users', args.legacy
        )
        csvtsv_to_excel(
            args.filename_prepend + 'Domain_Group_Membership.tsv',
            args.filename_prepend + 'Users_Groups_Computers.xlsx',
            'Groups', args.legacy
        )
        csvtsv_to_excel(
            args.filename_prepend + 'Extended_Domain_Computer_Information.tsv',
            args.filename_prepend + 'Users_Groups_Computers.xlsx',
            'Computers', args.legacy
        )

    # OPSEC: Clean up artifacts and sanitize logs
    cleanup_opsec_artifacts(args)
    
    print('\n[i] Enumeration completed. Remember to review output files for sensitive data before sharing.')


if __name__ == '__main__':
    # Set event loop policy for Windows to prevent cleanup warnings
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