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

subscription = sw_context.inputs['subscriptionId']
subscriptionName = sw_context.inputs['subscriptionName']
resourceGroupName = sw_context.inputs['resourceGroupName']
nsgName = sw_context.inputs['nsgName']
ruleName = sw_context.inputs['ruleName']

tenant = sw_context.inputs['tenant_id']
client_id = sw_context.inputs['azure_swimlane_id']
client_secret = sw_context.inputs['azure_swimlane_secret']
authority_url = 'https://login.microsoftonline.com/' + tenant
resource = 'https://management.azure.com/'
context = adal.AuthenticationContext(authority_url)
token = context.acquire_token_with_client_credentials(resource, client_id, client_secret)
headers = {'Authorization': 'Bearer ' + token['accessToken'], 'Content-Type': 'application/json'}
params = {'api-version': '2019-07-01'}
url = 'https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/networkSecurityGroups/{}'.format(subscription, resourceGroupName, nsgName)

current_ip_list = []
current_dest_list = []
current_dest_port_list = []
current_rule_dict = {}

previous_ip_list = []
previous_dest_list = []
previous_dest_port_list = []
previous_rule_dict = {}

sensitive_ports = ['20', '21', '22', '23', '25', '135', '137', '138', '139', '389', '445', '1433', '3306', '3389', '5800', '5900', '5901', '5985', '5986']

azure_nsg_change_dir = '/app/workspace/azure_nsg_change'
previous_directory = '{}/previous_rules'.format(azure_nsg_change_dir)
sub_dir = '{}/{}'.format(previous_directory, subscriptionName)
sub_resource_group_dir = '{}/{}'.format(sub_dir, resourceGroupName)
previous_dict_filename = '{}/{}-rule_{}.json'.format(sub_resource_group_dir, nsgName, ruleName)

response = requests.get(url, headers=headers, params=params)

json_object = json.loads(response.content)
security_rules = json_object['properties']['securityRules']

def create_directories():
	if not os.path.exists(azure_nsg_change_dir):
		os.makedirs(azure_nsg_change_dir)
	if not os.path.exists(previous_directory):
		os.makedirs(previous_directory)
	if not os.path.exists(sub_dir):
		os.makedirs(sub_dir)
	if not os.path.exists(sub_resource_group_dir):
		os.makedirs(sub_resource_group_dir)

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

def build_current_rule_dict():
    for rule in security_rules:
        s = SecurityRule(rule)
        if s.name() == ruleName:
            if keys_exists(rule, "properties", "destinationApplicationSecurityGroups") or keys_exists(rule, "properties", "sourceApplicationSecurityGroups"):
                pass
            else:
                s.add_dictionary_item('direction', s.direction())
                s.add_dictionary_item('protocol', s.protocol())
                s.add_dictionary_item('priority', s.priority())
                s.add_dictionary_item('action', s.access())
                s.add_dictionary_item('name', s.name())
                s.add_dictionary_item('resourceGroupName', s.resourceGroupName())
                s.add_src()
                s.add_dest()
                s.add_dest_port()

            # Add s.dictionary to current_rule_dict
            for key, value in s.get_dictionary().iteritems():
                current_rule_dict[key] = value
            # Add dictionary['src_list'] to current_ip_list
            for ip in current_rule_dict['src_list']:
               current_ip_list.append(ip)
    sw_outputs.append({'current_ip_list': current_ip_list})
    sw_outputs.append({'current_rule_dict': current_rule_dict})
    allowed_from_broad_network = False
    sensitive_port_found = False
    if current_rule_dict:
        if '*' in current_rule_dict['src_list'] or '0.0.0.0' in current_rule_dict['src_list'] or '0.0.0.0/0' in current_rule_dict['src_list']:
            allowed_from_broad_network = True
        else:
            for ip in current_rule_dict['src_list']:
                if '/' in ip:
                    cidr = int(ip.split('/')[1])
                    if cidr < 30:
                        allowed_from_broad_network = True
                        break
        sw_outputs.append({'action': 'Rule has been added or modified'})
        sw_outputs.append({'current_dest_port_list': current_rule_dict['dest_port_list']})
        # Detect sensitive ports
        if any(port in sensitive_ports for port in current_rule_dict['dest_port_list']):
            sensitive_port_found = True
            sw_outputs.append({'sensitive_port_found': 'true'})
    else:
        sw_outputs.append({'action': 'Rule has been removed'})

    if allowed_from_broad_network:
        sw_outputs.append({'allowed_from_broad_network': 'true'})
    else:
        sw_outputs.append({'allowed_from_broad_network': 'false'})
    if sensitive_port_found:
        sw_outputs.append({'sensitive_port_found': 'true'})
    else:
        sw_outputs.append({'sensitive_port_found': 'false'})

def build_previous_rule_dict():
    if os.path.isfile(previous_dict_filename):
        previous_rule_dict_json = json.load(open(previous_dict_filename))
        for key, value in previous_rule_dict_json.iteritems():
            previous_rule_dict['{}'.format(str(key))] = value
    sw_outputs.append({'previous_rule_dict': previous_rule_dict})
    if 'dest_port_list' in previous_rule_dict:
        sw_outputs.append({'previous_dest_port_list': previous_rule_dict['dest_port_list']})

def get_difference():
    current_port_list = []
    previous_ip_list = []
    previous_port_list = []
    print('previous_rule_dict: {}'.format(previous_rule_dict))
    if os.path.isfile(previous_dict_filename):
        if previous_rule_dict:
            previous_ip_list = previous_rule_dict['src_list']
            previous_port_list = previous_rule_dict['dest_port_list']
    sw_outputs.append({'previous_ip_list': previous_ip_list})

    if current_rule_dict:
        current_port_list = current_rule_dict['dest_port_list']

    added_ips = []
    removed_ips = []
    added_ips = list(set(current_ip_list) - set(previous_ip_list))
    removed_ips = list(set(previous_ip_list) - set(current_ip_list))
    added_ports = list(set(current_port_list) - set(previous_port_list))
    removed_ports = list(set(previous_port_list) - set(current_port_list))
    str_added_ips = [str(ip) for ip in added_ips]
    str_removed_ips = [str(ip) for ip in removed_ips]
    str_added_ports = [str(port) for port in added_ports]
    str_removed_ports = [str(port) for port in removed_ports]

    if len(added_ips) == 0 and len(removed_ips) == 0:
        ip_result = 'No change in IPs'
    elif len(added_ips) > 0 and len(removed_ips) == 0: # IPs added
        ip_result = 'IPs added: {}'.format(str_added_ips)
    elif len(removed_ips) > 0 and len(added_ips) == 0: # IPs removed
        ip_result = 'IPs removed: {}'.format(str_removed_ips)
    elif len(added_ips) > 0 and len(removed_ips) > 0: # IPs both added and removed
        ip_result = 'IPs added: {}, IPs removed: {}'.format(str_added_ips, str_removed_ips)

    if len(added_ports) == 0 and len(removed_ports) == 0:
        port_result = 'No change in ports'
    elif len(added_ports) > 0 and len(removed_ports) == 0: # Ports added
        port_result = 'Ports added: {}'.format(str_added_ports)
    elif len(removed_ports) > 0 and len(added_ports) == 0: # Ports removed
        port_result = 'Ports removed: {}'.format(str_removed_ports)
    elif len(added_ports) > 0 and len(removed_ports) > 0: # Ports both added and removed
        port_result = 'Ports added: {}, Ports removed: {}'.format(str_added_ports, str_removed_ports)

    previous_ip_count = len(previous_ip_list)
    current_ip_count = len(current_ip_list)
    added_ip_count = len(added_ips)
    removed_ip_count = len(removed_ips)

    sw_outputs.append({'previous_ip_count': previous_ip_count})
    sw_outputs.append({'current_ip_count': current_ip_count})
    sw_outputs.append({'added_ip_count': added_ip_count})
    sw_outputs.append({'removed_ip_count': removed_ip_count})
    sw_outputs.append({'ip_result': ip_result})
    sw_outputs.append({'port_result': port_result})

def write_previous_dict_to_file():
    json.dump(current_rule_dict, open(previous_dict_filename, 'w'))

def set_script_finished():
    sw_outputs.append({'script_finished': 'true'})

create_directories()
build_current_rule_dict()
build_previous_rule_dict()
get_difference()
write_previous_dict_to_file()
set_script_finished()