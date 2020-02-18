import os
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.sql import SqlManagementClient

current_rule_dict = {}
previous_rule_dict = {}
client_id = sw_context.inputs['azure_swimlane_id']
secret = sw_context.inputs['azure_swimlane_secret']
tenant = sw_context.inputs['azure_tenant_id']
subscription = sw_context.inputs['subscriptionId']
subscriptionName = sw_context.inputs['subscriptionName']
resourceGroupName = sw_context.inputs['resourceGroupName']
sqlServer = sw_context.inputs['sqlServer']
previous_directory = '/app/workspace/azure_sql_firewall_change/previous_rules'
sub_dir = '{}/{}'.format(previous_directory, subscriptionName)
sub_resource_group_dir = '{}/{}'.format(sub_dir, resourceGroupName)
previous_dict_filename = '{}/{}.json'.format(sub_resource_group_dir, sqlServer)
subscription_id = os.environ.get(
    'AZURE_SUBSCRIPTION_ID',
    subscription)
credentials = ServicePrincipalCredentials(
    client_id = client_id,
    secret = secret,
    tenant = tenant
)
sql_client = SqlManagementClient(credentials, subscription_id)
firewall_rules = sql_client.firewall_rules.list_by_server(resourceGroupName, sqlServer)

def create_directories():
    if not os.path.exists(previous_directory):
        os.makedirs(previous_directory)
    if not os.path.exists(sub_dir):
        os.makedirs(sub_dir)
    if not os.path.exists(sub_resource_group_dir):
        os.makedirs(sub_resource_group_dir)

def generate_current_rule_dict():
    for firewall_rule in firewall_rules:
        start_ip = str(firewall_rule.start_ip_address)
        end_ip = str(firewall_rule.end_ip_address)
        ip_range = '%s:%s' % (start_ip, end_ip)
        rule_name = str(firewall_rule.name)
        if start_ip == end_ip:
            current_rule_dict['%s' % (rule_name)] = start_ip
        else:
            current_rule_dict['%s' % (rule_name)] = ip_range

def generate_previous_rule_dict():
    if os.path.isfile(previous_dict_filename):
        previous_rule_dict_json = json.load(open(previous_dict_filename))
        for rule, ip in previous_rule_dict_json.iteritems():
            previous_rule_dict['%s' % (str(rule))] = '%s' % (str(ip))

def get_difference():
    current_ip_list = []
    previous_ip_list = []
    rules_added = []
    rules_removed = []
    for rule, ip in current_rule_dict.iteritems():
        current_ip_list.append(str(ip))
    for rule, ip in previous_rule_dict.iteritems():
        previous_ip_list.append(str(ip))

    difference = set(previous_ip_list).symmetric_difference(set(current_ip_list))
    sw_outputs.append({'difference': list(difference)})

    for ip in list(difference):
        for rule, current_ip in current_rule_dict.iteritems(): # IPs added
            if ip == current_ip:
                rules_added.append('%s: %s' % (str(rule), str(current_ip)))
        for rule, previous_ip in previous_rule_dict.iteritems(): # IPs removed
            if ip == previous_ip:
                rules_removed.append('%s: %s' % (str(rule), str(previous_ip)))

    if len(list(difference)) == 0:
        result = 'IPs are the same - no change in rules'
        sw_outputs.append({'result': result})
    elif len(rules_added) > 0 and len(rules_removed) == 0:
        result = 'Rules were added: %s' % (rules_added)
        sw_outputs.append({'result': result})
    elif len(rules_removed) > 0 and len(rules_added) == 0:
        result = 'Rules were removed: %s' % (rules_removed)
        sw_outputs.append({'result': result})
    elif len(rules_added) > 0 and len(rules_removed) > 0:
        result = 'Added: %s, Removed: %s' % (rules_added, rules_removed)
        sw_outputs.append({'result': result})
    else:
        sw_outputs.append({'result': 'something else occurred'})

    current_ip_count = len(current_ip_list)
    previous_ip_count = len(previous_ip_list)

    sw_outputs.append({'current_ip_count': current_ip_count})
    sw_outputs.append({'previous_ip_count': previous_ip_count})

def write_previous_dict_to_file():
    json.dump(current_rule_dict, open(previous_dict_filename, 'w'))

def set_script_finished():
    sw_outputs.append({'script_finished': 'true'})

create_directories()
generate_current_rule_dict()
generate_previous_rule_dict()
get_difference()
write_previous_dict_to_file()
set_script_finished()