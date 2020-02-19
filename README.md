# Scripts

## send_crowdstrike_to_splunk_hec.py

A script that is run in a cronjob to read from the CrowdStrike replicator directory (CrowdStrike data) and then send the logs to a load balancer. It would then evenly distribute the logs across Splunk indexers.

## swimlane - get_nsg_baseline.py

Creates a baseline for all Network Security Groups in every Azure subscription to then later use to compare with the difference script.

## swimlane - get_nsg_difference.py

An alert is triggered from a Splunk search when there is a modification to an Azure Network Security Group, which then sends details to Swimlane. In Swimlane this script is ran, which reaches out to the Azure API to gather details from the specified Network Security Group firewall rule and then compares the IPs and ports with the baseline, which will then show what was added or removed.

## swimlane - get_sql_firewall_baseline.py

Creates a baseline for Azure SQL firewall rules for all SQL servers within every Azure subscription to then later use to compare with the difference script.

## swimlane - get_sql_firewall_difference.py

An alert is triggered from a Splunk search when there is a modification to an Azure SQL firewall, which then sends details to Swimlane. In Swimlane this script is ran, which reaches out to the Azure API to gather details from the SQL firewall and then compares the IPs in the baseline to show what was added or removed.

## Get-AzureRoleAssignment-Baseline.ps1

Creates a baseline for Azure role assignments within every subscription.

## Get-AzureRoleAssignment-Difference.ps1

Uses the Azure PowerShell module to gather role assignments within a specified subscription and then compares that to the baseline, which then shows which user was added or removed from a role.
