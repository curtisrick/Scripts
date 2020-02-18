
$subscriptions = Get-AzSubscription

Connect-AzAccount

function Create-Directories {
    
    param (
        [parameter (Mandatory=$true, position=0)]
        [String]$subscription
    )

    $previous_dir = "C:\Users\RCurtis\scripts\AzureRoleAssignment\previous_test"
    $previous_sub_dir = "$previous_dir\$subscription"

    If (-Not (Test-Path -LiteralPath $previous_dir)) {
        New-Item -ItemType Directory -Path $previous_dir
    }
    If (-Not (Test-Path -LiteralPath $previous_sub_dir)) {
        New-Item -ItemType Directory -Path $previous_sub_dir
    }
}

function Build-CurrentUsers {
    # Get current list of role assignments (Az)
    $global:current_users = Get-AzRoleAssignment | Select-Object ObjectId, DisplayName, RoleDefinitionId, RoleDefinitionName, SignInName, ObjectType
}

function Write-PreviousFile {

    param (
        [parameter (Mandatory=$true, position=0)]
        [String]$subscription
    )

    # Write current as previous to file
    $previous_dir = "C:\Users\RCurtis\scripts\AzureRoleAssignment\previous_test"
    $previous_sub_dir = "$previous_dir\$subscription"
    $previous_file_path = "$previous_sub_dir\roleAssignments.csv"
    $global:current_users | Export-Csv -Path $previous_file_path -NoTypeInformation
}

$timeTaken = Measure-Command {
    foreach ($subscription in $subscriptions) {
        Write-Host "Subscription $($subscription.Name): $($subscription.Id)"
        Write-Host ""
        Set-AzContext -SubscriptionId $subscription.Id
        Create-Directories $subscription.Name
        Build-CurrentUsers
        Write-PreviousFile $subscription.Name
    }
}
