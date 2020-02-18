import os
import re
import json
import adal
import requests

# SecurityRule class

class SecurityRule():
    def __init__(self, json_object):
        self.rule = json_object
        self.dictionary = {}

    def name(self):
        return self.rule['name']

    def access(self):
        return self.rule['properties']['access']

    def direction(self):
        return self.rule['properties']['direction']

    def protocol(self):
        return self.rule['properties']['protocol']

    def priority(self):
        return self.rule['properties']['priority']

    def description(self):
        return self.rule['properties']['description']

    def src(self):
        if self.rule['properties']['sourceAddressPrefixes']:
            self.src_addrs = self.rule['properties']['sourceAddressPrefixes']
        elif self.rule['properties']['sourceAddressPrefix']:
            self.src_addrs = self.rule['properties']['sourceAddressPrefix']
        return self.src_addrs

    def add_src(self):
        current_ip_list = []
        if isinstance(self.src(), list):
            for ip in self.src():
                current_ip_list.append(ip)
            self.add_dictionary_item('src_list', current_ip_list)
        elif isinstance(self.src(), basestring):
            current_ip_list.append(self.src())
            self.add_dictionary_item('src_list', current_ip_list)

    def dest(self):
        if self.rule['properties']['destinationAddressPrefixes']:
            self.dest_addrs = self.rule['properties']['destinationAddressPrefixes']
        elif self.rule['properties']['destinationAddressPrefix']:
            self.dest_addrs = self.rule['properties']['destinationAddressPrefix']
        return self.dest_addrs

    def add_dest(self):
        current_dest_list = []
        if isinstance(self.dest(), list):
            for dest in self.dest():
                current_dest_list.append(dest)
            self.add_dictionary_item('dest_list', current_dest_list)
        elif isinstance(self.dest(), basestring):
            current_dest_list.append(self.dest())
            self.add_dictionary_item('dest_list', current_dest_list)

    def dest_port(self):
        if self.rule['properties']['destinationPortRanges']:
            self.dest_ports = self.rule['properties']['destinationPortRanges']
        elif self.rule['properties']['destinationPortRange']:
            self.dest_ports = self.rule['properties']['destinationPortRange']
        return self.dest_ports

    def add_dest_port(self):
        current_dest_port_list = []
        if isinstance(self.dest_port(), list):
            for port in self.dest_port():
                current_dest_port_list.append(port)
            self.add_dictionary_item('dest_port_list', current_dest_port_list)
        elif isinstance(self.dest_port(), basestring):
            current_dest_port_list.append(self.dest_port())
            self.add_dictionary_item('dest_port_list', current_dest_port_list)

    def resourceGroupName(self):
        resourceGroupName = re.search('\/subscriptions\/[a-zA-Z0-9\-]+\/resourceGroups\/([a-zA-Z0-9\-\_]+)\/', self.rule['id'], re.IGNORECASE)
        return resourceGroupName.group(1)

    def get_dictionary(self):
        return self.dictionary

    def add_dictionary_item(self, key, value):
        self.dictionary[key] = value

# get_nsg_difference Azure Python SDK script

tenant = sw_context.inputs['tenant_id']
client_id = sw_context.inputs['azure_swimlane_id']
client_secret = sw_context.inputs['azure_swimlane_secret']
authority_url = 'https://login.microsoftonline.com/' + tenant
resource = 'https://management.azure.com/'
context = adal.AuthenticationContext(authority_url)
token = context.acquire_token_with_client_credentials(resource, client_id, client_secret)
headers = {'Authorization': 'Bearer ' + token['accessToken'], 'Content-Type': 'application/json'}
params = {'api-version': '2019-07-01'}

subscriptions_dict = {}

def create_directories(subscription, resourceGroupName, nsgName, ruleName):
    azure_nsg_change_dir = 'azure_nsg_change'
    previous_directory = '{}/previous_nsg_dir'.format(azure_nsg_change_dir)
    sub_dir = '{}/{}'.format(previous_directory, subscription)
    sub_resource_group_dir = '{}/{}'.format(sub_dir, resourceGroupName)
    rule_filename = '{}/{}-rule_{}.json'.format(sub_resource_group_dir, nsgName, ruleName)
    if not os.path.exists(azure_nsg_change_dir):
        os.makedirs(azure_nsg_change_dir)
    if not os.path.exists(previous_directory):
        os.makedirs(previous_directory)
    if not os.path.exists(sub_dir):
        os.makedirs(sub_dir)
    if not os.path.exists(sub_resource_group_dir):
        os.makedirs(sub_resource_group_dir)

def set_script_finished():
    sw_outputs.append({'script_finished': 'true'})

def keys_exists(element, *keys):
    '''
    Check if *keys (nested) exists in `element` (dict).
    '''
    if not isinstance(element, dict):
        raise AttributeError('keys_exists() expects dict as first argument.')
    if len(keys) == 0:
        raise AttributeError('keys_exists() expects at least two arguments, one given.')

    _element = element
    for key in keys:
        try:
            _element = _element[key]
        except KeyError:
            return False
    return True

def build_subscriptions_dict():
    params = {'api-version': '2019-06-01'}
    url = 'https://management.azure.com/subscriptions'
    response = requests.get(url, headers=headers, params=params)
    json_object = json.loads(response.content)
    subscriptions = json_object['value']

    for subscription in subscriptions:
        subscription_id = str(subscription['subscriptionId'])
        subscription_name = str(subscription['displayName'])

        subscriptions_dict[subscription_id] = subscription_name

def write_rule_to_file(subscription, resourceGroupName, nsgName, ruleName, ruleDict):
    azure_nsg_change_dir = 'azure_nsg_change'
    previous_directory = '{}/previous_nsg_dir'.format(azure_nsg_change_dir)
    sub_dir = '{}/{}'.format(previous_directory, subscription)
    sub_resource_group_dir = '{}/{}'.format(sub_dir, resourceGroupName)
    rule_filename = '{}/{}-rule_{}.json'.format(sub_resource_group_dir, nsgName, ruleName)

    create_directories(subscription, resourceGroupName, nsgName, ruleName)
    json.dump(ruleDict, open(rule_filename, 'w'))

def list_all_nsgs_by_sub(sub_id, sub_name):
    nsgs_dict = {}
    json_dump_filename = 'json_dump_{}.json'.format(sub_name)
    params = {'api-version': '2019-09-01'}
    url = 'https://management.azure.com/subscriptions/{}/providers/Microsoft.Network/networkSecurityGroups'.format(sub_id)
    response = requests.get(url, headers=headers, params=params)
    json_object = json.loads(response.content)
    json_dump = json.dumps(response.json(), indent=2, separators=(',', ': '))

    network_security_groups = json_object['value']

    print(sub_name)

    for nsg in network_security_groups:
        nsg_name = nsg['name']
        security_rules = nsg['properties']['securityRules']
        nsgs_dict[str(nsg_name)] = {}
        for rule in security_rules:
            if keys_exists(rule, "properties", "destinationApplicationSecurityGroups") or keys_exists(rule, "properties", "sourceApplicationSecurityGroups"):
                print('****** Application Security Groups! ******')
                print('App Rule: {}'.format(rule))
            else:
                s = SecurityRule(rule)
                s.add_dictionary_item('direction', s.direction())
                s.add_dictionary_item('protocol', s.protocol())
                s.add_dictionary_item('priority', s.priority())
                s.add_dictionary_item('action', s.access())
                s.add_dictionary_item('name', s.name())
                s.add_dictionary_item('resourceGroupName', s.resourceGroupName())
                s.add_src()
                s.add_dest()
                s.add_dest_port()
                nsgs_dict[str(nsg_name)][str(s.name())] = s.get_dictionary()

    for nsg_name, rules in nsgs_dict.iteritems():
        for rule_name, properties in rules.iteritems():
            write_rule_to_file(sub_name, str(properties['resourceGroupName']), nsg_name, rule_name, properties)

build_subscriptions_dict()

for sub_id, sub_name in subscriptions_dict.iteritems():
    list_all_nsgs_by_sub(sub_id, sub_name)

set_script_finished()