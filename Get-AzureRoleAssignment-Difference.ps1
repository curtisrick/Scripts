$passwd = ConvertTo-SecureString '' -AsPlainText -Force
$pscredential = New-Object System.Management.Automation.PSCredential('xxxxx', $passwd)
$subscription = 'xxxxx'
$tenantId = 'xxxxx'

Connect-AzAccount -ServicePrincipal -Credential $pscredential -Tenant $tenantId
Set-AzContext -SubscriptionId $subscription

$previous_dir = "C:\Users\RCurtis\scripts\AzureRoleAssignment\previous"
$previous_sub_dir = "$previous_dir\$subscription"
$global:previous_file_path = "$previous_sub_dir\roleAssignments.csv"
$global:previous_users = @()

function Create-Directories {
    If (-Not (Test-Path -LiteralPath $previous_dir)) {
        New-Item -ItemType Directory -Path $previous_dir
    }
    If (-Not (Test-Path -LiteralPath $previous_sub_dir)) {
        New-Item -ItemType Directory -Path $previous_sub_dir
    }
}

function Send-Email {

    param (
        [parameter (Mandatory=$true, position=0)]
        [String]$Message
    )

    $From = "xxxxx@xxxxx.com"
    $To = "xxxxx@xxxxx.com"
    $Subject = "Azure Role Assignment Change"

    $Body = "<h2>An Azure Role Assignment Change was Detected</h2>"
    $Body += "$($Message)"

    $SMTPServer = "xxxxx"
    $SMTPPort = "25"

    Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body -BodyAsHtml -SmtpServer $SMTPServer -Port $SMTPPort
}

function Build-CurrentUsers {
    # Get current list of role assignments (Az)
    $global:current_users = Get-AzRoleAssignment | Select-Object ObjectId, DisplayName, RoleDefinitionId, RoleDefinitionName, SignInName, ObjectType

    # Get current list of role assignments (AzureRm)
    #$global:current_users = Get-AzureRmRoleAssignment | Select-Object ObjectId, DisplayName, RoleDefinitionId, RoleDefinitionName, SignInName, ObjectType
}

function Load-PreviousFile {
    # Import previous role assignments from file
    If (Test-Path -LiteralPath $global:previous_file_path) {
        $global:previous_users = Import-Csv -Path $global:previous_file_path
    }
}

function Get-Difference {
    # Compare the 2 lists and show what is different
    #$difference_result = Compare-Object -ReferenceObject $global:current_users -DifferenceObject $global:previous_users -Property ObjectId, RoleDefinitionId | Format-Table

    $difference = Compare-Object -ReferenceObject $global:current_users -DifferenceObject $global:previous_users -Property ObjectId, RoleDefinitionId, RoleDefinitionName

    $added = $difference | Where-Object -FilterScript {$_.SideIndicator -eq '<='}
    $removed = $difference | Where-Object -FilterScript {$_.SideIndicator -eq '=>'}

    $email_message = ""

    If ($difference.Length -eq 0) {
        Write-Host "Nothing modified"
    } Else {
        Write-Host "difference length: $($difference.Length)"
        foreach ($added_user in $added) {
            foreach ($current_user in $global:current_users) {
                If ($added_user.ObjectId -eq $current_user.ObjectId -and $added_user.RoleDefinitionId -eq $current_user.RoleDefinitionId) {
                    $added_message = "User '$($current_user.DisplayName)' was added to role '$($current_user.RoleDefinitionName)'"
                    Write-Host $added_message
                    $email_message += "$($added_message)<br>"
                    #Send-Email $added_message
                }
            }
        }
        foreach ($removed_user in $removed) {
            foreach ($previous_user in $global:previous_users) {
                If ($removed_user.ObjectId -eq $previous_user.ObjectId -and $removed_user.RoleDefinitionId -eq $previous_user.RoleDefinitionId) {
                    $removed_message = "User '$($previous_user.DisplayName)' was removed from role '$($previous_user.RoleDefinitionName)'"
                    Write-Host $removed_message
                    $email_message += "$($removed_message)<br>"
                    #Send-Email $removed_message
                }
            }
        }
    }
    Send-Email $email_message
}

function Write-PreviousFile {
    # Write current as previous to file
    $global:current_users | Export-Csv -Path $global:previous_file_path -NoTypeInformation
}

Create-Directories
Build-CurrentUsers
Load-PreviousFile
Get-Difference
Write-PreviousFile