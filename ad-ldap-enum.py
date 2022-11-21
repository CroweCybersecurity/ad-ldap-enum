#!/usr/bin/env python

# Author:: Eric DePree
# Date::   2015 - 2017

# Modified: dekanfrus - October 15, 2019 
# Retrieve the 'userPassword' field for user accounts, which is commonly used in SSO applications. Password is stored in cleartex.

'''An LDAP Active Directory enumerator. The script queries Active Directory over LDAP for users, groups and computers.
   This information is correlated and output to the console showing groups, their membership and other user information.
   The script supports null and authenticated Active Directory access.'''

import traceback
import ldap3
from ldap3.utils.log import set_library_log_detail_level, OFF, ERROR, BASIC, PROTOCOL, NETWORK, EXTENDED
import datetime
from time import gmtime
import logging
import argparse
from getpass import getpass
import argcomplete

class ADUser(object):
    '''A representation of a user in Active Directory. Class variables are instantiated to a 'safe'
       state so when the object is used during processing it can be assumed that all properties have
       some sort of value.'''
    distinguished_name = ''
    sam_account_name = ''
    user_account_control = ''
    primary_group_id = ''
    comment = ''
    description = ''
    home_directory = ''
    display_name = ''
    mail = ''
    password_last_set = ''
    last_logon = ''
    profile_path = ''
    locked_out = 'NO'
    logon_script = ''
    user_password = ''

    def __init__(self, retrieved_attributes):
        if 'distinguishedName' in retrieved_attributes:
            self.distinguished_name = retrieved_attributes['distinguishedName'][0]
        if 'sAMAccountName' in retrieved_attributes:
            self.sam_account_name = retrieved_attributes['sAMAccountName'][0]
        if 'userAccountControl' in retrieved_attributes:
            self.user_account_control = retrieved_attributes['userAccountControl'][0]
        if 'primaryGroupID' in retrieved_attributes:
            self.primary_group_id = retrieved_attributes['primaryGroupID'][0]
        if 'comment' in retrieved_attributes:
            self.comment = str(retrieved_attributes['comment'][0]).replace('\t', '*TAB*').replace('\r', '*CR*').replace('\n', '*LF*')
        if 'description' in retrieved_attributes:
            self.description = str(retrieved_attributes['description'][0]).replace('\t', '*TAB*').replace('\r', '*CR*').replace('\n', '*LF*')
        if 'homeDirectory' in retrieved_attributes:
            self.home_directory = retrieved_attributes['homeDirectory'][0]
        if 'displayName' in retrieved_attributes:
            self.display_name = retrieved_attributes['displayName'][0]
        if 'mail' in retrieved_attributes:
            self.mail = retrieved_attributes['mail'][0]
        if 'pwdLastSet' in retrieved_attributes:
            self.password_last_set = retrieved_attributes['pwdLastSet'][0]
        if 'lastLogon' in retrieved_attributes:
            self.last_logon = retrieved_attributes['lastLogon'][0]
        if 'profilePath' in retrieved_attributes:
            self.profile_path = retrieved_attributes['profilePath'][0]
        if 'lockoutTime' in retrieved_attributes and retrieved_attributes['lockoutTime'][0] != '0':
            self.locked_out = 'YES'
        if 'scriptPath' in retrieved_attributes:
            self.logon_script = retrieved_attributes['scriptPath'][0]
        if 'userPassword' in retrieved_attributes:
            self.user_password = retrieved_attributes['userPassword'][0]

    def get_account_flags(self):
        _output_string = ''

        if self.user_account_control:
            _account_disabled = 2
            _account_locked = 16
            _passwd_cant_change = 64
            _normal_account = 512
            _dont_expire_password = 65536
            _smartcard_required = 262144
            _password_expired = 8388608

            _uac_value = int(self.user_account_control)

            if _uac_value & _account_disabled:
                _output_string += 'DISABLED '
            if _uac_value & _account_locked:
                _output_string += 'LOCKED '
            if _uac_value & _normal_account:
                _output_string += 'NORMAL '
            if _uac_value & _password_expired:
                _output_string += 'PASSWORD_EXPIRED '
            if _uac_value & _dont_expire_password:
                _output_string += 'DONT_EXPIRE_PASSWORD '
            if _uac_value & _smartcard_required:
                _output_string += 'SMARTCARD_REQUIRED '
            if _uac_value & _passwd_cant_change:
                _output_string += 'PASSWD_CANT_CHANGE '

        return _output_string

    def get_password_last_set_date(self):
        if (self.password_last_set != '') and (self.password_last_set != '0') and (int(self.password_last_set) != 0):
            last_set_int = int(self.password_last_set)
            epoch_time = (last_set_int / 10000000) - 11644473600
            last_set_time = datetime.datetime.fromtimestamp(epoch_time)
            return last_set_time.strftime('%m-%d-%y %H:%M:%S')

        return self.password_last_set

    def get_last_logon_date(self):
        if (self.last_logon != '') and (self.last_logon != '0') and (int(self.last_logon) != 0):
            last_logon_int = int(self.last_logon)
            epoch_time = (last_logon_int / 10000000) - 11644473600
            last_logon_time = datetime.datetime.fromtimestamp(epoch_time)
            return last_logon_time.strftime('%m-%d-%y %H:%M:%S')

        return self.last_logon

class ADComputer(object):
    '''A representation of a computer in Active Directory. Class variables are instantiated to a 'safe'
       state so when the object is used during processing it can be assumed that all properties have
       some sort of value.'''
    distinguished_name = ''
    sam_account_name = ''
    primary_group_id = ''
    operating_system = ''
    operating_system_hotfix = ''
    operating_system_service_pack = ''
    operating_system_version = ''
    service_principal_names = []

    def __init__(self, retrieved_attributes):
        if 'distinguishedName' in retrieved_attributes:
            self.distinguished_name = retrieved_attributes['distinguishedName'][0]
        if 'sAMAccountName' in retrieved_attributes:
            self.sam_account_name = retrieved_attributes['sAMAccountName'][0]
        if 'primaryGroupID' in retrieved_attributes:
            self.primary_group_id = retrieved_attributes['primaryGroupID'][0]
        if 'operatingSystem' in retrieved_attributes:
            self.operating_system = retrieved_attributes['operatingSystem'][0]
        if 'operatingSystemHotfix' in retrieved_attributes:
            self.operating_system_hotfix = retrieved_attributes['operatingSystemHotfix'][0]
        if 'operatingSystemServicePack' in retrieved_attributes:
            self.operating_system_service_pack = retrieved_attributes['operatingSystemServicePack'][0]
        if 'operatingSystemVersion' in retrieved_attributes:
            self.operating_system_version = retrieved_attributes['operatingSystemVersion'][0]
        if 'servicePrincipalName' in retrieved_attributes:
            self.service_principal_names = retrieved_attributes['servicePrincipalName']

class ADGroup(object):
    '''A representation of a group in Active Directory. Class variables are instantiated to a 'safe'
       state so when the object is used during processing it can be assumed that all properties have
       some sort of value.'''
    distinguished_name = ''
    sam_account_name = ''
    primary_group_token = ''
    members = []
    is_large_group = False

    def __init__(self, retrieved_attributes):
        if 'distinguishedName' in retrieved_attributes:
            self.distinguished_name = retrieved_attributes['distinguishedName'][0]
        if 'sAMAccountName' in retrieved_attributes:
            self.sam_account_name = retrieved_attributes['sAMAccountName'][0]
        if 'primaryGroupToken' in retrieved_attributes:
            self.primary_group_token = retrieved_attributes['primaryGroupToken'][0]
        if 'member' in retrieved_attributes:
            self.members = retrieved_attributes['member']
            if any(dictionary_key.startswith('member;range') for dictionary_key in list(retrieved_attributes.keys())):
                self.is_large_group = True

def ldap_queries(ldap_client, base_dn, explode_nested_groups, query_limit, legacy):
    '''Main worker function for the script.'''
    users_dictionary = {}
    groups_dictionary = {}
    computers_dictionary = {}
    group_id_to_dn_dictionary = {}

    # LDAP filters
    user_filter = '(objectcategory=user)'
    user_attributes = ['distinguishedName', 'sAMAccountName', 'userAccountControl', 'primaryGroupID', 'comment', 'description', 'homeDirectory', 'displayName', 'mail', 'pwdLastSet', 'lastLogon', 'profilePath', 'lockoutTime', 'scriptPath', 'userPassword']

    group_filter = '(objectcategory=group)'
    group_attributes = ['distinguishedName', 'sAMAccountName', 'member', 'primaryGroupToken']

    computer_filters = '(objectcategory=computer)'
    computer_attributes = ['distinguishedName', 'sAMAccountName', 'primaryGroupID', 'operatingSystem', 'operatingSystemHotfix', 'operatingSystemServicePack', 'operatingSystemVersion', 'servicePrincipalName']

    # LDAP queries
    print('[-] Querying users...')
    users = query_ldap_with_paging(ldap_client, base_dn, user_filter, user_attributes, query_limit, ADUser)
    print('[i] Found %i users' % len(users))
    print('[-] Querying groups...')
    groups = query_ldap_with_paging(ldap_client, base_dn, group_filter, group_attributes, query_limit, ADGroup)
    print('[i] Found %i groups' % len(groups))
    print('[-] Querying computers...')
    computers = query_ldap_with_paging(ldap_client, base_dn, computer_filters, computer_attributes, query_limit, ADComputer)
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

    # Loop through each group. If the membership is a range, then query AD to get the full group membership
    print('[-] Exploding large groups...')
    for group_key, group_object in groups_dictionary.items():
        if group_object.is_large_group:
            print('Getting full membership for "%s"' % group_key)
            groups_dictionary[group_key].members = get_membership(ldap_client, base_dn, group_key, query_limit)

    # Build group membership
    print('[-] Building group membership...')
    print('[i] %i groups were found.' % len(list(groups_dictionary.keys())))

    current_group_number = 0
    _output_dictionary = []
    for grp in list(groups_dictionary.keys()):
        current_group_number += 1
        _output_dictionary += process_group(users_dictionary, groups_dictionary, computers_dictionary, grp, explode_nested_groups, None, [], legacy)

        if current_group_number % 1000 == 0:
            print('[-] Processing group %i...' % current_group_number)
    print('[-] Done')

    # TODO: This could create output duplicates. It should be fixed at some point.
    # Add users if they have the group set as their primary ID as the group.
    # Additionally, add extended domain user information to a text file.
    user_information_filename = '{0}Extended_Domain_User_Information.csv'.format(args.filename_prepend).strip()
    if legacy:
        user_information_filename = user_information_filename.replace('csv', 'tsv')
    with open(user_information_filename, 'w') as user_information_file:
        print('[-] Writing domain user information to "%s"...' % user_information_file.name)
        if not legacy:
            user_information_file.write('SAM Account Name,Status,Locked Out,Distinguished Name,User Password,Display Name,Email,Home Directory,Profile Path,Logon Script Path,Password Last Set,Last Logon,User Comment,Description\n')
        else:
            user_information_file.write('SAM Account Name\tStatus\tLocked Out\tUser Password\tDisplay Name\tEmail\tHome Directory\tProfile Path\tLogon Script Path\tPassword Last Set\tLast Logon\tUser Comment\tDescription\n')

        for user_object in list(users_dictionary.values()):
            if user_object.primary_group_id and user_object.primary_group_id in group_id_to_dn_dictionary:
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
                if not legacy:
                    temp_list_a.append(user_object.distinguished_name)
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
                _output_dictionary.append(temp_list_b)

                tmp_element = ''
                for x, binary_string in enumerate(temp_list_a[1:]):
                    binary_string = str(binary_string).strip()
                    if binary_string[:2] == "b'" or binary_string[:2] == 'b"':
                        binary_string = binary_string[2:]
                        binary_string = binary_string[:-1]
                    if legacy and 'dc=' in binary_string.lower(): # Skip distinguishedName
                        continue
                    if not legacy and ',' in binary_string:
                        binary_string = '"' + binary_string + '"'
                    if x == len(temp_list_a[1:])-1 :
                        tmp_element += binary_string + '\n'
                    elif legacy:
                        tmp_element += binary_string + '\t'
                    else:
                        tmp_element += binary_string + ','
                
                user_information_file.write(tmp_element)

    # Write Domain Computer Information
    computer_information_filename = '{0}Extended_Domain_Computer_Information.csv'.format(args.filename_prepend).strip()
    if legacy:
        computer_information_filename = computer_information_filename.replace('csv', 'tsv')
    with open(computer_information_filename, 'w') as computer_information_file:
        print('[-] Writing domain computer information to "%s"...' % computer_information_file.name)
        if not legacy:
            computer_information_file.write('SAM Account Name,OS,OS Hotfix,OS Service Pack,OS Version,Distinguished Name,SQL SPNs,RA SPNS,Share SPNs,Mail SPNs,Auth SPNs,Backup SPNs,Management SPNs,Other SPNs\n')
        else:
            computer_information_file.write('SAM Account Name\tOS\tOS Hotfix\tOS Service Pack\tOS Version\tSQL SPNs\tRA SPNS\tShare SPNs\tMail SPNs\tAuth SPNs\tBackup SPNs\tManagement SPNs\tOther SPNs\n')


        # TODO: This could create output duplicates. It should be fixed at some point.
        # Add computers if they have the group set as their primary ID as the group
        for computer_object in list(computers_dictionary.values()):
            if computer_object.primary_group_id:
                grp_dn = group_id_to_dn_dictionary[computer_object.primary_group_id]

                temp_list_a = []
                temp_list_b = []

                temp_list_a.append(groups_dictionary[grp_dn].sam_account_name)
                temp_list_a.append(computer_object.sam_account_name)

                temp_list_b.append(computer_object.sam_account_name)
                temp_list_b.append(computer_object.operating_system)
                temp_list_b.append(computer_object.operating_system_hotfix)
                temp_list_b.append(computer_object.operating_system_service_pack)
                temp_list_b.append(computer_object.operating_system_version)
                if not legacy:
                    temp_list_b.append(computer_object.distinguished_name)
                [temp_list_b.append(','.join(map(str, item))) for item in parse_spns(computer_object.service_principal_names)]

                tmp_element = ''
                for x, binary_string in enumerate(temp_list_b):
                    binary_string = str(binary_string).strip()
                    if binary_string[:2] == "b'" or binary_string[:2] == 'b"':
                        binary_string = binary_string[2:]
                        binary_string = binary_string[:-1]
                    if legacy and 'dc=' in binary_string.lower(): # Skip distinguishedName
                        continue
                    if not legacy and ',' in binary_string:
                        binary_string = '"' + binary_string + '"'
                    if x == len(temp_list_b)-1 :
                        tmp_element += binary_string + '\n'
                    elif legacy:
                        tmp_element += binary_string + '\t'
                    else:
                        tmp_element += binary_string + ','
                computer_information_file.write(tmp_element)
                _output_dictionary.append(temp_list_a)

    # Write Group Memberships
    group_membership_filename = '{0}Domain_Group_Membership.csv'.format(args.filename_prepend).strip()
    if legacy:
        group_membership_filename = group_membership_filename.replace('csv', 'tsv')
    with open(group_membership_filename, 'w') as group_membership_file:
        print('[-] Writing membership information to "%s"...' % group_membership_file.name)
        if not legacy:
            group_membership_file.write('Group Name,Member SAM Account Name,Member Status,Group Distinguished Name\n')
        else:
            group_membership_file.write('Group Name\tMember SAM Account Name\tMember Status\n')

        for element in _output_dictionary:
            tmp_element = ''
            for x, binary_string in enumerate(element):
                binary_string = str(binary_string).strip()
                if binary_string[:2] == "b'" or binary_string[:2] == 'b"':
                    binary_string = binary_string[2:]
                    binary_string = binary_string[:-1]
                if legacy and 'dc=' in binary_string.lower(): # Skip distinguishedName
                    continue
                if not legacy and ',' in binary_string:
                        binary_string = '"' + binary_string + '"'
                if x == len(element)-1 :
                    tmp_element += binary_string + '\n'
                elif legacy:
                    tmp_element += binary_string + '\t'
                else:
                    tmp_element += binary_string + ','
                
            group_membership_file.write(tmp_element)

def process_group(users_dictionary, groups_dictionary, computers_dictionary, group_distinguished_name, explode_nested_bool, base_group_name, groups_seen, legacy):
    '''Builds group membership for a specified group.'''
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
            temp_list = [group_sam_name, user_member.sam_account_name, user_member.get_account_flags(), group_distinguished_name]
            if legacy:
                temp_list.pop(-1)
            group_dictionary.append(temp_list)

        # Process computers.
        elif member in computers_dictionary:
            temp_list = [group_sam_name, computers_dictionary[member].sam_account_name, '', group_distinguished_name]
            if legacy:
                temp_list.pop(-1)
            group_dictionary.append(temp_list)

        # Process groups.
        elif member in groups_dictionary:
            if not explode_nested_bool or (explode_nested_bool and base_group_name is None):
                temp_list = [group_sam_name, groups_dictionary[member].sam_account_name, '', group_distinguished_name]
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
                    group_dictionary += process_group(users_dictionary, groups_dictionary, computers_dictionary, member, True, group_sam_name, groups_seen, legacy)

    return group_dictionary

def query_ldap_with_paging(ldap_client, base_dn, search_filter_custom, attributes, query_limit, output_object=None, page_size=1000):
    '''Get all the Active Directory results from LDAP using a paging approach.
       By default Active Directory will return 1,000 results per query before it errors out.'''

    # Paging for AD LDAP Queries
    output_list= []
    entry_list = ldap_client.extend.standard.paged_search(search_base = base_dn, search_filter = search_filter_custom, search_scope = ldap3.SUBTREE, paged_criticality = True, time_limit = query_limit, attributes = attributes, paged_size = page_size, generator=False)

    # Append Page to Results
    # Some of the entry_list responses may not have a 'raw_attributes' key due to those responses being search metadata
    for entry in entry_list:
        if 'raw_attributes' in entry and output_object is None:
            output_list.append(entry['raw_attributes'])
        elif 'raw_attributes' in entry:
            output_list.append(output_object(entry['raw_attributes']))
        # else: # This displays that response metadata without 'raw_attributes'
            # print(entry)

    return output_list

def parse_spns(service_principle_names):
    temp_sql_spns = []
    sql_spn_strings = ['MSSQLSvc', 'gateway', 'hbase', 'HBase', 'hdb', 'hdfs', 'hive', 'Kafka', 'mongod', 'mongos', 'MSOLAPSvc', 'MSSQL', 'oracle', 'postgres']
    temp_ra_spns = []
    ra_spn_strings = ['vnc', 'WSMAN', 'TERMSRV', 'RPC', 'HTTP', 'https', 'jboss']
    temp_share_spns = []
    share_spn_strings = ['cifs', 'CIFS', 'afpserver', 'AFServer', 'nfs', 'Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04', 'ftp', 'iSCSITarget']
    temp_mail_spns = []
    mail_spn_strings = ['SMTPSVC', 'SMTP', 'exchangeAB', 'exchangeMDB', 'exchangeRFR', 'IMAP', 'IMAP4', 'POP', 'POP3']
    temp_auth_spns = []
    auth_spn_strings = ['ldap', 'aradminsvc', 'DNS', 'FIMService', 'GC', 'kadmin', 'OA60']
    temp_backup_spns = []
    backup_spn_strings = ['AcronisAgent', 'Agent VProRecovery Norton Ghost 12.0', 'Backup Exec System Recovery Agent 6.0', 'LiveState Recovery Agent 6.0']
    temp_management_spns = []
    management_spn_strings = ['AdtServer', 'AgpmServer', 'CAXOsoftEngine', 'CAARCserveRHAEngine', 'Cognos', 'ckp_pdp', 'CmRcService', 'Hyper-V Replica Service', 'Microsoft Virtual Console Service', 'MSClusterVirtualServer', 'MSServerCluster', 'MSOMHSvc', 'MSOMSdkSvc', 'PCNSCLNT', 'SCVMM']
    temp_other_spns = []

    for spn in service_principle_names:
        spn = str(spn)
        if spn[:2] == "b'" or spn[:2] == 'b"':
            spn = spn[2:]
            spn = spn[:-1]
        if spn.split('/')[0] in sql_spn_strings:
            temp_sql_spns.append(spn)
        elif spn.split('/')[0] in ra_spn_strings:
            temp_ra_spns.append(spn)
        elif spn.split('/')[0] in share_spn_strings:
            temp_share_spns.append(spn)
        elif spn.split('/')[0] in mail_spn_strings:
            temp_mail_spns.append(spn)
        elif spn.split('/')[0] in auth_spn_strings:
            temp_auth_spns.append(spn)
        elif spn.split('/')[0] in backup_spn_strings:
            temp_backup_spns.append(spn)
        elif spn.split('/')[0] in management_spn_strings:
            temp_management_spns.append(spn)
        else:
            temp_other_spns.append(spn)

    return [temp_sql_spns, temp_ra_spns, temp_share_spns, temp_mail_spns, temp_auth_spns, temp_backup_spns, temp_management_spns, temp_other_spns]

def get_membership(ldap_client, base_dn, group_dn, query_limit):
    '''Queries the membership of an Active Directory group. For large groups Active Directory will
       not return the full membership by default but will instead return partial results. Additional
       processing is needed to get the full membership.'''
    members_list = []

     # RFC 4515 sanitation.
    sanitized_group_dn = str(group_dn).replace('(', '\\28').replace(')', '\\29').replace('*', '\\2a').replace('\\', '\\5c')

    membership_filter = '(&(|(objectcategory=user)(objectcategory=group)(objectcategory=computer))(memberOf={0}))'.format(sanitized_group_dn)
    membership_results = query_ldap_with_paging(ldap_client, base_dn, membership_filter, ['distinguishedName'], query_limit)

    for element in membership_results:
        members_list.append(element['distinguishedName'])

    return members_list

if __name__ == '__main__':
    # Command line arguments
    parser = argparse.ArgumentParser(description='Active Directory LDAP Enumerator')
    parser.add_argument('-s', '--secure', dest='secure_comm', action='store_true', help='Connect to LDAP over SSL/TLS')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='LDAP server connection timeout in seconds')
    parser.add_argument('-ql', '--query_limit', type=int, default=30, help='LDAP server query timeout in seconds')
    parser.add_argument('--verbosity', default='ERROR', choices=['OFF', 'ERROR', 'BASIC', 'PROTOCOL', 'NETWORK', 'EXTENDED'], help='Log file LDAP verbosity level')
    parser.add_argument('-lf', '--log_file', help='Log text file path')
    parser.add_argument('-k', '--kerberos', help='Use Kerberos authentication')
    parser.add_argument('-p', '--password', help='Authentication account\'s password or "LM:NTLM".')
    parser.add_argument('-P', '--prompt', dest='password_prompt', action='store_true', help='Prompt for the authentication account\'s password.')
    parser.add_argument('-o', '--prepend', dest='filename_prepend', default='ad-ldap-enum_', help='Prepend a string to all output file names\' CSV.')
    parser.add_argument('--legacy', action='store_true', help='Gather and output attributes using the old python-ldap package .tsv format (will be deprecated)')
    parser.add_argument('-4', '--inet', action='store_true', help='Only use IPv4 networking (default prefer IPv4)')
    parser.add_argument('-6', '--inet6', action='store_true', help='Only use IPv6 networking (default prefer IPv4)')
    
    method = parser.add_mutually_exclusive_group(required=True)
    method.add_argument('-n', '--null', dest='null_session', action='store_true', help='Use a null binding to authenticate to LDAP.')
    method.add_argument('-u', '--username', help='Authentication account\'s username.')
    method.add_argument('-dn', '--distinguished_name', help='Authentication account\'s distinguished name')

    server_group = parser.add_argument_group('Server Parameters')
    server_group.add_argument('-l', '--server', required=True, dest='ldap_server', help='FQDN/IP address of the LDAP server.')
    server_group.add_argument('--port', type=int, help='TCP port of the LDAP server.')
    server_group.add_argument('-d', '--domain', required=True, help='Authentication account\'s domain. If an alternative domain is not specified, this will be also used as the Base DN for searching LDAP.')
    server_group.add_argument('-a', '--alt-domain', dest='alt_domain', help='Alternative FQDN to use as the Base DN for searching LDAP.')
    server_group.add_argument('-e', '--nested', dest='nested_groups', action='store_true', help='Expand nested groups.')

    # Parse arguments
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    # If --prompt then overwrite args.password now
    if args.password_prompt is True or (not args.password and not args.null_session):
        args.password = getpass()

    # If Kerberos, require user
    if args.kerberos and (not args.user or not args.domain):
        print('[e] A user and domain must both be specified with Kerberos authentication usage.') 
        exit(1)

    # Set Logger format
    if args.verbosity != 'OFF' or args.log_file:
        if not args.log_file:
            args.log_file = 'ad-ldap-enum_Log.txt'
        if args.verbosity == 'OFF':
            args.verbosity = 'BASIC'
        print('[-] Writing logs to "%s"...' % args.log_file)
        logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%dT%H:%M:%SZ', level=logging.DEBUG, filename=args.log_file, filemode='a')
        # Force UTC
        logging.Formatter.converter = gmtime

    # Configure ldap3 package verbosity level
    if args.verbosity == 'ERROR':
        set_library_log_detail_level(ERROR)
    elif args.verbosity == 'BASIC':
        set_library_log_detail_level(BASIC)
    elif args.verbosity == 'PROTOCOL':
        set_library_log_detail_level(PROTOCOL)
    elif args.verbosity == 'NETWORK':
        set_library_log_detail_level(NETWORK)
    elif args.verbosity == 'EXTENDED':
        set_library_log_detail_level(EXTENDED)
    else:
        set_library_log_detail_level(OFF)

    # Build the baseDN
    if not args.distinguished_name:
        if args.alt_domain:
            formatted_domain_name = args.alt_domain.replace('.', ',dc=')
        else:
            formatted_domain_name = args.domain.replace('.', ',dc=')

        base_dn = 'dc={0}'.format(formatted_domain_name)
    else:
        base_dn = args.distinguished_name
    print('[-] Using BaseDN of "%s"...' % base_dn)

    try:
        # Connect to LDAP
        if args.inet6:
            ip_mode = 'IP_V6_ONLY'
        elif args.inet:
            ip_mode = 'IP_V4_ONLY'
        else:
            ip_mode = 'IP_V4_PREFERRED'
        
        if args.secure_comm:
            if not args.port:
                args.port = 636
            ldap_client = ldap3.Server(args.ldap_server, port = args.port, use_ssl = True, get_info=ldap3.ALL, mode = ip_mode, connect_timeout=args.timeout)
        else:
            if not args.port:
                args.port = 389
            ldap_client = ldap3.Server(args.ldap_server, port = args.port, get_info=ldap3.ALL, mode = ip_mode, connect_timeout=args.timeout)

        print('[-] Connecting to LDAP server at "%s:%i"...' % (args.ldap_server, args.port))

        # LDAP Authentication
        if args.null_session:
            ldap_client = ldap3.Connection(ldap_client, read_only=True, raise_exceptions=True, receive_timeout=args.timeout, auto_range=True, return_empty_attributes=False)
        elif args.distinguished_name:
            ldap_client = ldap3.Connection(ldap_client, user=args.distinguished_name, password=args.password, read_only=True, raise_exceptions=True, receive_timeout=args.timeout, auto_range=True, return_empty_attributes=False)
        elif args.kerberos:
            ldap_client = ldap3.Connection(ldap_client, user=args.domain + '/' + args.username, read_only=True, raise_exceptions=True, receive_timeout=args.timeout, auto_range=True, return_empty_attributes=False, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS)
        else:
            ldap_client = ldap3.Connection(ldap_client, user=args.domain + '\\' + args.username, password=args.password, sasl_credentials=(ldap3.ReverseDnsSetting.OPTIONAL_RESOLVE_ALL_ADDRESSES,), read_only=True, raise_exceptions=True, authentication=ldap3.NTLM, receive_timeout=args.timeout, auto_range=True, return_empty_attributes=False)
        ldap_client.bind()
    except ldap3.core.exceptions.LDAPOperationsErrorResult as e:
        if 'perform this operation a successful bind' in str(e):
            print('[e] In order to perform this operation, a successful bind must be completed on the connection.')
        logging.error(traceback.format_exc())
        exit(1)
    except ldap3.core.exceptions.LDAPSocketOpenError as e:
        if 'invalid server address' in str(e):
            print('[e] An invalid server address was provided.')
        logging.error(traceback.format_exc())
        exit(1)
    except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
        if 'invalidCredentials' in str(e):
            print('[e] Invalid credentials or domain were provided.')
        logging.error(traceback.format_exc())
        exit(1)
    except Exception as e:
        print(traceback.format_exc())
        logging.error(traceback.format_exc())
        exit(1)

    print('[-] Success')
    # Query LDAP
    try:
        ldap_queries(ldap_client, base_dn, args.nested_groups, args.query_limit, args.legacy)
        ldap_client.unbind()
    except ldap3.core.exceptions.LDAPAttributeError as e:
        if 'invalid attribute type' in str(e):
            print('[e] An invalid attribute type was provided.')
        logging.error(traceback.format_exc())
        exit(1)
    except Exception as e:
        print(traceback.format_exc())
        logging.error(traceback.format_exc())
        exit(1)
