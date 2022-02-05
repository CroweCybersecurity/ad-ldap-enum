#!/usr/bin/env python

# Author:: Eric DePree
# Date::   2015 - 2017

# Modified: dekanfrus - October 15, 2019 
# Retrieve the 'userPassword' field for user accounts, which is commonly used in SSO applications. Password is stored in cleartex.

'''An LDAP Active Directory enumerator. The script queries Active Directory over LDAP for users, groups and computers.
   This information is correlated and output to the console showing groups, their membership and other user information.
   The script supports null and authenticated Active Directory access.'''

import sys
import ldap3
import datetime
import logging
import argparse
import getpass
import argcomplete

from collections import deque

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

def ldap_queries(ldap_client, base_dn, explode_nested_groups):
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
    logging.info('Querying users')
    users = query_ldap_with_paging(ldap_client, base_dn, user_filter, user_attributes, ADUser)
    logging.info('Querying groups')
    groups = query_ldap_with_paging(ldap_client, base_dn, group_filter, group_attributes, ADGroup)
    logging.info('Querying computers')
    computers = query_ldap_with_paging(ldap_client, base_dn, computer_filters, computer_attributes, ADComputer)

    # LDAP dictionaries
    logging.info('Building users dictionary')
    for element in users:
        users_dictionary[element.distinguished_name] = element

    logging.info('Building groups dictionary')
    for element in groups:
        group_id_to_dn_dictionary[element.primary_group_token] = element.distinguished_name
        groups_dictionary[element.distinguished_name] = element

    logging.info('Building computers dictionary')
    for element in computers:
        computers_dictionary[element.distinguished_name] = element

    # Loop through each group. If the membership is a range then query AD to get the full group membership
    logging.info('Exploding large groups')
    for group_key, group_object in groups_dictionary.items():
        if group_object.is_large_group:
            logging.debug('Getting full membership for [%s]', group_key)
            groups_dictionary[group_key].members = get_membership_with_ranges(ldap_client, base_dn, group_key)

    # Build group membership
    logging.info('Building group membership')
    logging.info('There is a total of [%i] groups', len(list(groups_dictionary.keys())))

    current_group_number = 0
    _output_dictionary = []
    for grp in list(groups_dictionary.keys()):
        current_group_number += 1
        _output_dictionary += process_group(users_dictionary, groups_dictionary, computers_dictionary, grp, explode_nested_groups, None, [])

        if current_group_number % 1000 == 0:
            logging.info('Processing group [%i]', current_group_number)

    # TODO: This could create output duplicates. It should be fixed at some point.
    # Add users if they have the group set as their primary ID as the group.
    # Additionally, add extended domain user information to a text file.
    user_information_filename = '{0}_Extended_Domain_User_Information.csv'.format(args.filename_prepend).strip()
    with open(user_information_filename, 'w') as user_information_file:
        logging.info('Writing domain user information to [%s]', user_information_file.name)
        user_information_file.write('SAM Account Name,Status,Locked Out,Distinguished Name,User Password,Display Name,Email,Home Directory,Profile Path,Logon Script Path,Password Last Set,Last Logon,User Comment,Description\n')

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
                    binary_string = str(binary_string)
                    if binary_string[:2] == "b'":
                        binary_string = binary_string[2:]
                    if binary_string[-1:] == "'":
                        binary_string = binary_string[:-1]
                    if x == len(temp_list_a[1:])-1 :
                        tmp_element += binary_string + '\n'
                    else:
                        tmp_element += binary_string + '\t'
                
                user_information_file.write(tmp_element) #'\t'.join(str(temp_list_a[1:])) + '\n')

    # Write Domain Computer Information
    computer_information_filename = '{0}_Extended_Domain_Computer_Information.csv'.format(args.filename_prepend).strip()
    with open(computer_information_filename, 'w') as computer_information_file:
        logging.info('Writing domain computer information to [%s]', computer_information_file.name)
        computer_information_file.write('SAM Account Name,OS,OS Hotfix,OS Service Pack,OS Version,Distinguished Name,SQL SPNs,RA SPNS,Share SPNs,Mail SPNs,Auth SPNs,Backup SPNs,Management SPNs,Other SPNs\n')

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
                temp_list_b.append(computer_object.distinguished_name)
                [temp_list_b.append(','.join(map(str, item))) for item in parse_spns(computer_object.service_principal_names)]

                tmp_element = ''
                for x, binary_string in enumerate(temp_list_b):
                    binary_string = str(binary_string)
                    if binary_string[:2] == "b'":
                        binary_string = binary_string[2:]
                    if binary_string[-1:] == "'":
                        binary_string = binary_string[:-1]
                    if x == len(temp_list_b)-1 :
                        tmp_element += binary_string + '\n'
                    else:
                        tmp_element += binary_string + '\t'
                computer_information_file.write(tmp_element)
                _output_dictionary.append(temp_list_a)

    # Write Group Memberships
    group_membership_filename = '{0}_Domain_Group_Membership.csv'.format(args.filename_prepend).strip()
    with open(group_membership_filename, 'w') as group_membership_file:
        logging.info('Writing membership information to [%s]', group_membership_file.name)
        group_membership_file.write('Group Name,SAM Account Name,Status,Distinguished Name\n')

        for element in _output_dictionary:
            tmp_element = ''
            for x, binary_string in enumerate(element):
                binary_string = str(binary_string)
                if binary_string[:2] == "b'":
                    binary_string = binary_string[2:]
                if binary_string[-1:] == "'":
                    binary_string = binary_string[:-1]
                if x == len(element)-1 :
                    tmp_element += binary_string + '\n'
                else:
                    tmp_element += binary_string + '\t'
                
            group_membership_file.write(tmp_element)

def process_group(users_dictionary, groups_dictionary, computers_dictionary, group_distinguished_name, explode_nested, base_group_name, groups_seen):
    '''Builds group membership for a specified group.'''
    # Store assorted group information.
    group_dictionary = []

    # Query SAM name or used redefined SAM name if processing a nested group.
    if base_group_name is None:
        group_sam_name = groups_dictionary[group_distinguished_name].sam_account_name
    elif base_group_name is not None:
        group_sam_name = base_group_name

    # Add empty groups to the Domain Group Membership list for full visibility.
    if not groups_dictionary[group_distinguished_name].members:
        temp_list = [group_sam_name, '', '', groups_dictionary[group_distinguished_name]]
        group_dictionary.append(temp_list)

    # Add users/groups/computer if they are a 'memberOf' the group
    for member in groups_dictionary[group_distinguished_name].members:
        # Process users.
        if member in users_dictionary:
            user_member = users_dictionary[member]

            temp_list = [group_sam_name, user_member.sam_account_name, user_member.get_account_flags(), groups_dictionary[group_distinguished_name]]
            group_dictionary.append(temp_list)

        # Process computers.
        elif member in computers_dictionary:
            temp_list = [group_sam_name, computers_dictionary[member].sam_account_name, '', groups_dictionary[group_distinguished_name]]
            group_dictionary.append(temp_list)

        # Process groups.
        elif member in groups_dictionary:
            if not explode_nested or (explode_nested and base_group_name is None):
                temp_list = [group_sam_name, groups_dictionary[member].sam_account_name, '', groups_dictionary[group_distinguished_name]]
                group_dictionary.append(temp_list)

            if explode_nested:
                # Stop processing the chain if a circular reference is detected.
                if member in groups_seen:
                    pass
                # Process a nested group.
                else:
                    groups_seen.append(member)
                    group_dictionary += process_group(users_dictionary, groups_dictionary, computers_dictionary, member, True, group_sam_name, groups_seen)

    return group_dictionary

def query_ldap_with_paging(ldap_client, base_dn, search_filter, attributes, output_object=None, page_size=1000):
    '''Get all the Active Directory results from LDAP using a paging approach.
       By default Active Directory will return 1,000 results per query before it errors out.'''

    # Paging for AD LDAP Queries
    entry_list = ldap_client.search(search_base = base_dn, search_filter = search_filter, attributes = attributes, paged_size = page_size, generator=False)
    for entry in entry_list:
        print(entry['attributes'])
    total_entries = len(entry_list)
    print('Total entries retrieved:', total_entries)

    return entry_list

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

        if spn.split(b'/')[0] in sql_spn_strings:
            temp_sql_spns.append(spn)
        elif spn.split(b'/')[0] in ra_spn_strings:
            temp_ra_spns.append(spn)
        elif spn.split(b'/')[0] in share_spn_strings:
            temp_share_spns.append(spn)
        elif spn.split(b'/')[0] in mail_spn_strings:
            temp_mail_spns.append(spn)
        elif spn.split(b'/')[0] in auth_spn_strings:
            temp_auth_spns.append(spn)
        elif spn.split(b'/')[0] in backup_spn_strings:
            temp_backup_spns.append(spn)
        elif spn.split(b'/')[0] in management_spn_strings:
            temp_management_spns.append(spn)
        else:
            temp_other_spns.append(spn)

    return [temp_sql_spns, temp_ra_spns, temp_share_spns, temp_mail_spns, temp_auth_spns, temp_backup_spns, temp_management_spns, temp_other_spns]

def get_membership_with_ranges(ldap_client, base_dn, group_dn):
    '''Queries the membership of an Active Directory group. For large groups Active Directory will
       not return the full membership by default but will instead return partial results. Additional
       processing is needed to get the full membership.'''
    output_array = []

    # RFC 4515 sanitation.
    sanatized_group_dn = str(group_dn).replace('(', '\\28').replace(')', '\\29').replace('*', '\\2a').replace('\\', '\\5c')

    membership_filter = '(&(|(objectcategory=user)(objectcategory=group)(objectcategory=computer))(memberof={0}))'.format(sanatized_group_dn)
    membership_results = query_ldap_with_paging(ldap_client, base_dn, membership_filter, ['distinguishedName'])

    for element in membership_results:
        output_array.append(element['distinguishedName'][0])

    return output_array

if __name__ == '__main__':
    start_time = datetime.datetime.now()

    # Print to stdout in addition to log
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    # Set a format which is simpler for console use
    formatter = logging.Formatter('%(levelname)-1s: %(message)s')

    # Command line arguments
    parser = argparse.ArgumentParser(description='Active Directory LDAP Enumerator')
    server_group = parser.add_argument_group('Server Parameters')
    server_group.add_argument('-l', '--server', required=True, dest='ldap_server', help='IP address of the LDAP server.')
    server_group.add_argument('-d', '--domain', required=True, dest='domain', help='Authentication account\'s FQDN. If an alternative domain is not specified this will be also used as the Base DN for searching LDAP.')
    server_group.add_argument('-a', '--alt-domain', dest='alt_domain', help='Alternative FQDN to use as the Base DN for searching LDAP.')
    server_group.add_argument('-e', '--nested', dest='nested_groups', action='store_true', help='Expand nested groups.')
    authentication_group = parser.add_argument_group('Authentication Parameters')
    authentication_group.add_argument('-n', '--null', dest='null_session', action='store_true', help='Use a null binding to authenticate to LDAP.')
    authentication_group.add_argument('-s', '--secure', dest='secure_comm', action='store_true', help='Connect to LDAP over SSL')
    authentication_group.add_argument('-u', '--username', dest='username', help='Authentication account\'s username.')
    authentication_group.add_argument('-p', '--password', dest='password', help='Authentication account\'s password.')
    authentication_group.add_argument('-P', '--prompt', dest='password_prompt', action='store_true', help='Prompt for the authentication account\'s password.')    
    parser.add_argument('-v', '--verbose', dest='verbosity', action='store_true', help='Display debugging information.')
    parser.add_argument('-o', '--prepend', dest='filename_prepend', default='', help='Prepend a string to all output file names.')
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

   # If --prompt then overwrite args.password now
    if args.password_prompt is True:
        args.password = getpass.getpass()
   
    # Instantiate logger
    if args.verbosity is True:
        logLevel = 10
    else:
        logLevel = 20

    logging.basicConfig(format='%(asctime)-19s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logLevel)

    # Build the baseDN
    if args.alt_domain:
        formatted_domain_name = args.alt_domain.replace('.', ',dc=')
    else:
        formatted_domain_name = args.domain.replace('.', ',dc=')

    base_dn = 'dc={0}'.format(formatted_domain_name)
    logging.debug('Using BaseDN of [%s]', base_dn)

    try:
        # Connect to LDAP
        if args.secure_comm:
            ldap_client = ldap3.Server(args.ldap_server, port = 636, use_ssl = True)
        else:
            ldap_client = ldap3.Server(args.ldap_server, get_info=ldap3.ALL)

        logging.debug('Connecting to LDAP server at [%s]', ldap_client.address_info)

        # LDAP Authentication
        if args.null_session is True:
            ldap_client = ldap3.Connection(ldap_client)
        else:
            ldap_client = ldap3.Connection(ldap_client, user=base_dn, password=args.password)
        ldap_client.bind()
    except ldap3.LDAPException as e:
        logging.error('An operations error has occurred')
        logging.debug(e)
        sys.exit(0)

    # Query LDAP
    try:
        ldap_queries(ldap_client, base_dn, args.nested_groups)
        ldap_client.unbind()
    except ldap3.LDAPException as e:
        logging.error('An operations error has occurred')
        logging.debug(e)
    finally:
        end_time = datetime.datetime.now()
        logging.info('Elapsed Time [%s]', end_time - start_time)
        sys.exit(0)
