import os
import re
import json
import adal
import requests
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.sql import SqlManagementClient

client_id = '' # Swimlane
client_secret = '' # Swimlane

subscriptions_dict = {}
sub_sql_servers_dict = {}

def build_subscriptions_dict():
    authority_url = 'https://login.microsoftonline.com/' + tenant
    resource = 'https://management.azure.com/'
    context = adal.AuthenticationContext(authority_url)
    token = context.acquire_token_with_client_credentials(resource, client_id, client_secret)
    headers = {'Authorization': 'Bearer ' + token['accessToken'], 'Content-Type': 'application/json'}
    params = {'api-version': '2019-06-01'}
    url = 'https://management.azure.com/subscriptions'
    response = requests.get(url, headers=headers, params=params)
    json_object = json.loads(response.content)
    subscriptions = json_object['value']

    for subscription in subscriptions:
        subscription_id = str(subscription['subscriptionId'])
	subscription_name = str(subscription['displayName'])
	subscriptions_dict[subscription_id] = subscription_name

def build_sql_servers_dict(subscription_id, subscription_name):

    sub_sql_servers_dict[subscription_id] = {}

    subscription_id = os.environ.get(
        'AZURE_SUBSCRIPTION_ID',
        subscription_id)
    credentials = ServicePrincipalCredentials(
        client_id = client_id,
        secret = client_secret,
        tenant = tenant
    )
    
    sql_client = SqlManagementClient(credentials, subscription_id)
    
    sql_servers = sql_client.servers.list()
    
    for server in sql_servers:
        resourceGroupName = re.search('\/subscriptions\/[a-zA-Z0-9\-]+\/[a-zA-Z]+\/([a-zA-Z0-9\-\_]+)\/', server.id, re.IGNORECASE)
	resourceGroupName = resourceGroupName.group(1)
	sub_sql_servers_dict[subscription_id][server.name] = resourceGroupName

def create_firewall_rule_files(subscription_id, sql_server, resource_group_name):

    rule_dict = {}

    subscription_id = os.environ.get(
        'AZURE_SUBSCRIPTION_ID',
        subscription_id)
    credentials = ServicePrincipalCredentials(
        client_id = client_id,
        secret = client_secret,
        tenant = tenant
    )
    
    sql_client = SqlManagementClient(credentials, subscription_id)

    subscription_name = subscriptions_dict[subscription_id]
    print('{}/{}: {}/{}'.format(subscription_name, subscription_id, resource_group_name, sql_server))
    firewall_rules = sql_client.firewall_rules.list_by_server(resource_group_name, sql_server)
    
    for firewall_rule in firewall_rules:
	start_ip = str(firewall_rule.start_ip_address)
	end_ip = str(firewall_rule.end_ip_address)
	ip_range = '{}:{}'.format(start_ip, end_ip)
	rule_name = str(firewall_rule.name)
	if start_ip == end_ip:
            rule_dict[rule_name] = start_ip
        else:
            rule_dict[rule_name] = ip_range

    print('rule_dict: {}'.format(rule_dict))
    write_rule_dict_to_file(subscription_name, resource_group_name, sql_server, rule_dict)

def create_directories(azure_sql_server_dir, previous_directory, sub_dir, sub_resource_group_dir):
    if not os.path.exists(azure_sql_server_dir):
        os.makedirs(azure_sql_server_dir)
    if not os.path.exists(previous_directory):
        os.makedirs(previous_directory)
    if not os.path.exists(sub_dir):
        os.makedirs(sub_dir)
    if not os.path.exists(sub_resource_group_dir):
        os.makedirs(sub_resource_group_dir)

def write_rule_dict_to_file(subscription_name, resource_group_name, sql_server, rule_dict):
    azure_sql_server_dir = 'azure-sql-firewall'
    previous_directory = '{}/previous_rules'.format(azure_sql_server_dir)
    sub_dir = '{}/{}'.format(previous_directory, subscription_name)
    sub_resource_group_dir = '{}/{}'.format(sub_dir, resource_group_name)
    rule_dict_filename = '{}/{}.json'.format(sub_resource_group_dir, sql_server)

    create_directories(azure_sql_server_dir, previous_directory, sub_dir, sub_resource_group_dir)

    json.dump(rule_dict, open(rule_dict_filename, 'w'))

def main():

    build_subscriptions_dict()

    print('subscriptions_dict: {}'.format(subscriptions_dict))

    for subscriptionId, subscriptionName in subscriptions_dict.iteritems():
        build_sql_servers_dict(subscriptionId, subscriptionName)
    
    print('sub_sql_servers_dict: {}'.format(sub_sql_servers_dict))
    
    for subscription_id, sql_servers in sub_sql_servers_dict.iteritems():
        print('subscription: {}'.format(subscriptions_dict[subscription_id]))
        for sqlServer, resourceGroupName in sql_servers.iteritems():
            create_firewall_rule_files(subscription_id, sqlServer, resourceGroupName)

main()
