<#
.SYNOPSIS 
 Script is desigened to configure settings for Azure Resource PIM roles
.DESCRIPTION
DISCLAIMER
  THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
  INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  
  We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object
  code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software
  product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the
  Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims
  or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.
  Please note: None of the conditions outlined in the disclaimer above will supersede the terms and conditions contained within
  the Premier Customer Services Description.
  .Parameter Role
  Name of the role to be configured. Valid values are: Owner, Contributor, Reader, Backup Contributor, Snapshot Contributor etc
  .Parameter id
  id of the Azure resource to be configured for PIM. Example: /subscriptions/<subscription id>/resourceGroups/<resource group name>/providers/Microsoft.Storage/storageAccounts/<name>
  Can be passed as pipeline input.g  Can use alias ResourceId.
  .Parameter apiVersion
    API version to be used for the request. Default value is 2020-10-01
    .EXAMPLE
    Run the following command to configure Owner role for the storage account
    Set-AzureResourcePIMRolesGlobal -Role 'Owner' -Id '/subscriptions/<subscription id>/resourceGroups/<resource group name>/providers/Microsoft.Storage/storageAccounts/<name>'
    .EXAMPLE
    Run the following command to configure Owner role for the storage account receive id from pipeline
    get-storageaccount -Name <account name> -ResourceGroupName <resource group> | Set-AzureResourcePIMRolesGlobal -Role 'Owner'
    .EXAMPLE
    Run the following command to configure Owner role for the storage account using alias ResourceId
    Set-AzureResourcePIMRolesGlobal -Role 'Owner' -ResourceId '/subscriptions/<subscription id>/resourceGroups/<resource group name>/providers/Microsoft.Storage/storageAccounts/<name>'
#> 
 
 
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$role,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias('ResourceId')]
    [string]$Id,
    [string]$apiVersion = '2020-10-01'
)


#process rules for role enablement requirements
function enabledRules {
    param (
        $multifactorRequired,
        $justificationRequired,
        $ticketRequired
    )
    $enalledRulesArray = @()
    if ($multifactorRequired = 'true') {
        $enalledRulesArray += 'MultiFactorAuthentication'
    }
    elseif ($justificationRequired = 'true') {
        $enalledRulesArray += 'Justification'
    }
    elseif ($ticketRequired = 'true') {
        $enalledRulesArray += 'Ticket'
    }
    return $enalledRulesArray
}

function ValidateTimeFormat {
    param (
        $time,
        $ruleName,
        $expirationRequired
    )
    if ($time -match '^P(?:T(?:(\d+)H))?$' -and $ruleName -eq "Activation maximum duration (hours)") {
        Write-Verbose 'Expiration time format is valid rule Activation maximum duration (hours)'
        return $time
    }
    elseIf ($time -match '^P(?:(\d+)M)?(?:(\d+)D)?$' -and $ruleName -ne "Activation maximum duration (hours)" ) {
        Write-Verbose "Expiration time format is valid"
        return $time
    }
    elseif ([string]::isNullOrEmpty($time) -and $expirationRequired -eq 'false') {
        return $time
    }    
    else {
        Write-Error 'Expiration time format is invalid, please check answer file rules "Activation maximum duration (hours)","Allow permanent eligible assignment" or "Allow permanent active assignment" and ensure correct ISO 8601 format is used to decsribe time duration'
        exit
    }
    
   
}




#region Classes
class Target {
    [string]$caller 
    [string[]]$operations = @("All")
    [string]$level
}

#class for policy settings array 
class PolicyProperties {
    [array]$rules 
}

#root class for PIM polciies 
class PolicySettings {
    [PolicyProperties]$properties = [PolicyProperties]::New()
}
Class Enablement {
      
    [string[]]$enabledRules = @() # possible values "MultiFactorAuthentication", "Justification","Ticketing"
    [string]$id 
    [string]$ruleType = "RoleManagementPolicyEnablementRule"
    [Target]$target = [Target]::New()
    
}
Class Expiration {
    [bool]$isExpirationRequired
    [string]$maximumDuration # must use dateInterval , starting with PT and hours only 
    [string]$id
    [string]$ruleType = "RoleManagementPolicyExpirationRule"
    [Target]$target = [Target]::New()
}
Class Approval {
      
    [approvalSetting]$setting = [approvalSetting]::New()
    [string]$id 
    [string]$ruleType = "RoleManagementPolicyApprovalRule"
    [Target]$target = [Target]::New()

}
class Notification {
    [string] $id
    [string] $ruleType = "RoleManagementPolicyNotificationRule"
    [string] $notificationType = "Email"
    [ValidateSet('Approver', 'Requestor', 'Admin')]
    [string] $recipientType
    [string] $notificationLevel
    [bool] $isDefaultRecipientsEnabled
    [string[]] $notificationRecipients = @()
    [Target]$target = [Target]::New()
}
class approvalStage {
    [int]$approvalStageTimeOutInDays = 1
    [bool]$isApproverJustificationRequired = $true
    [int]$escalationTimeInMinutes = 0
    [bool]$isEscalationEnabled = $false
    [array]$primaryApprovers = @()
    #[array]$escalationApprovers = @()
}
class  approvalSetting {
    [bool]$isApprovalRequired
    [bool]$isApprovalRequiredForExtension = $false
    [bool]$isRequestorJustificationRequired = $true
    [string]$approvalMode = "SingleStage"
    [System.Collections.ArrayList]$approvalStages = @()
}
Class Approver {
    [string]$id
    [string]$description
    [string]$isBackup
    [ValidateSet('Group', 'User')]
    [string]$userType
}
#endregion

$roleDefenitionId = (Get-AzRoleDefinition -Name $role -Scope $Id).Id
Write-Verbose $roleDefenitionId

#region process answer file and create policy settings objects
$configData = Get-Content .\answer.json | ConvertFrom-Json -Depth 99





#region collect and backup current policy settings

$filter = '$filter'
$policyResult = (Invoke-AzRest -Path "$($id)/providers/Microsoft.Authorization/roleManagementPolicies?api-version=$($apiVersion)&$filter=roleDefinitionId%20eq%20'$($Id)/providers/Microsoft.Authorization/roleDefinitions/$($roleDefenitionId)'" -Method GET).Content 
$policyResult | Out-File ./policyResult.json -Force
$policyName = ($policyResult | ConvertFrom-Json).value.name
#endregion



#region Creating policy settings array

#create policy settings array
$policySettings = @()
#loop through rules in answer file and add valued to  policy settings array
forEach ($ruleEntry in $configData.rules) {
    switch ($ruleEntry.ruleName) {
        "Activation maximum duration (hours)" {
            $expiration = [Expiration]::New()
            $expiration.isExpirationRequired = $true
            $expiration.maximumDuration = ValidateTimeFormat -time $ruleEntry.maximumDuration -ruleName $ruleEntry.ruleName
            $expiration.id = "Expiration_EndUser_Assignment"
            $expiration.target.caller = "EndUser"
            $expiration.target.level = "Assignment"
            $policySettings += $expiration
        }
        "On activation, require" {
            $enablement = [Enablement]::New()
            $enablement.enabledRules = enabledRules -multifactorRequired $ruleEntry.multiFactorRequired -justificationRequired $ruleEntry.justificationRequired -ticketingRequired $ruleEntry.ticketingRequired
            $enablement.id = "Enablement_EndUser_Assignment"
            $enablement.target.caller = "EndUser"
            $enablement.target.level = "Assignment"
            $policySettings += $enablement

        }
       "Require approval to activate" {
            $Approval = [Approval]::New()
            $Approval.setting = $ruleEntry.setting
            $Approval.id = "Approval_EndUser_Assignment"
            $Approval.target.level = "Assigniment"
            $Approval.target.caller = $caller.Enduser
            $policySettings += $Approval
        }
        "Allow permanent eligible assignment" { 
            $expiration = [Expiration]::New()
            $expiration.isExpirationRequired = $ruleEntry.isExpirationRequired
            $expiration.maximumDuration = ValidateTimeFormat -time $ruleEntry.maximumDuration -expirationRequired $ruleEntry.isExpirationRequired
            $expiration.id = "Expiration_Admin_Eligibility"
            $expiration.target.caller = "Admin"
            $expiration.target.level = "Eligibility"
            $policySettings += $expiration
        }
       "Allow permanent active assignment" {
            $expiration = [Expiration]::New()
            $expiration.isExpirationRequired = $ruleEntry.isExpirationRequired
            $expiration.maximumDuration = ValidateTimeFormat -time $ruleEntry.maximumDuration -expirationRequired $ruleEntry.isExpirationRequired
            $expiration.id = "Expiration_Admin_Assignment"
            $expiration.target.caller = "Admin"
            $expiration.target.level = "Eligibility"
            $policySettings += $expiration

       }
         "On active assignment, require" { 
            $enablement = [Enablement]::New()
            $enablement.enabledRules = enabledRules -multifactorRequired $ruleEntry.multiFactorRequired -justificationRequired $ruleEntry.justificationRequired
            $enablement.id = "Enablement_Admin_Assignment"
            $enablement.target.caller = "Admin"
            $enablement.target.level = "Assignment"
            $policySettings += $enablement    
        }
        "Role assignment alert eligible" { 
            $notification = [Notification]::New()
            $notification.id = "Notification_Admin_Admin_Eligibility"
            $notification.target.caller = "Admin"
            $notification.target.level = "Eligibility"
            $notification.notificationLevel = "All"
            $notification.isDefaultRecipientsEnabled = $ruleEntry.isDefaultRecipientsEnabled
            $notification.notificationRecipients = $ruleEntry.notificationRecipients
            $notification.recipientType = "Admin"
            $policySettings += $notification
         }
        "Notification to the assigned user (assignee) eligible" { 
            $notification = [Notification]::New()
            $notification.id = "Notification_Requestor_Admin_Eligibility"
            $notification.recipientType = "Requestor"
            $notification.target.caller = "Admin"
            $notification.target.level = "Eligibility"
            $notification.notificationLevel = "All"
            $notification.isDefaultRecipientsEnabled = $ruleEntry.isDefaultRecipientsEnabled
            $notification.notificationRecipients = $ruleEntry.notificationRecipients
            $policySettings += $notification
         }
        "Request to approve a role assignment renewal/extension eligible" { 
            $notification = [Notification]::New()
            $notification.id = "Notification_Approver_Admin_Eligibility"
            $notification.recipientType = "Approver"
            $notification.target.caller = "Admin"
            $notification.target.level = "Eligibility"
            $notification.notificationLevel = "All"
            $notification.isDefaultRecipientsEnabled = $ruleEntry.isDefaultRecipientsEnabled
            $notification.notificationRecipients = $ruleEntry.notificationRecipients
            $policySettings += $notification
         }
        "Role assignment alert active" { 
            $notification = [Notification]::New()
            $notification.id = "Notification_Admin_Admin_Assignment"
            $notification.recipientType = "Admin"
            $notification.target.caller = "Admin"
            $notification.target.level = "Assignment"
            $notification.notificationLevel = "All"
            $notification.isDefaultRecipientsEnabled = $ruleEntry.isDefaultRecipientsEnabled
            $notification.notificationRecipients = $ruleEntry.notificationRecipients
            $policySettings += $notification
         }
       "Notification to the assigned user (assignee) active" {
            $notification = [Notification]::New()
            $notification.id = "Notification_Requestor_Admin_Assignment"
            $notification.recipientType = "Requestor"
            $notification.target.caller = "Admin"
            $notification.target.level = "Assignment"
            $notification.notificationLevel = "All"
            $notification.isDefaultRecipientsEnabled = $ruleEntry.isDefaultRecipientsEnabled
            $notification.notificationRecipients = $ruleEntry.notificationRecipients
            $policySettings += $notification
          }
        "Request to approve a role assignment renewal/extension active" { 
            $notification = [Notification]::New()
            $notification.id = "Notification_Approver_Admin_Assignment"
            $notification.recipientType = "Approver"
            $notification.target.caller = "Admin"
            $notification.target.level = "Assignment"
            $notification.notificationLevel = "All"
            $notification.isDefaultRecipientsEnabled = $ruleEntry.isDefaultRecipientsEnabled
            $notification.notificationRecipients = $ruleEntry.notificationRecipients
            $policySettings += $notification
         }
        "Role activation alert" { 
            $notification = [Notification]::New()
            $notification.id = "Notification_Admin_EndUser_Assignment"
            $notification.recipientType = "Admin"
            $notification.target.caller = "EndUser"
            $notification.target.level = "Assignment"
            $notification.notificationLevel = "All"
            $notification.isDefaultRecipientsEnabled = $ruleEntry.isDefaultRecipientsEnabled
            $notification.notificationRecipients = $ruleEntry.notificationRecipients
            $policySettings += $notification
         }
        "Notification to activated user (requestor)" { 
            $notification = [Notification]::New()
            $notification.id = "Notification_Requestor_EndUser_Assignment"
            $notification.recipientType = "Requestor"
            $notification.target.caller = "EndUser"
            $notification.target.level = "Activation"
            $notification.notificationLevel = "All"
            $notification.isDefaultRecipientsEnabled = $ruleEntry.isDefaultRecipientsEnabled
            $notification.notificationRecipients = $ruleEntry.notificationRecipients
            
            $policySettings += $notification
         }
    "Request to approve an activation" { 
            $notification = [Notification]::New()
            $notification.id = "Notification_Approver_EndUser_Assignment"
            $notification.recipientType = "Approver"
            $notification.target.caller = "EndUser"
            $notification.target.level = "Assignment"
            $notification.notificationLevel = "All"
            $notification.isDefaultRecipientsEnabled = $ruleEntry.isDefaultRecipientsEnabled
            $notification.notificationRecipients = $ruleEntry.notificationRecipients
            
            $policySettings += $notification
         }

    }
    
}

#endregion


#create policy root object add policy array and convert to json
$policyObject = [PolicySettings]::New()
$policyObject.properties.rules = $policySettings
$policyUpdate = $policyObject | ConvertTo-Json -Depth 99
Write-Verbose $policyUpdate

#update policy
$result = Invoke-AzRest -Path "$($Id)/providers/Microsoft.Authorization/roleManagementPolicies/$($policyName)?api-version=$($apiVersion)" -Method PATCH -Payload $policyUpdate

If ($result.StatusCode -eq 200) {
    Write-Information "Policy updated successfully"
    write-verbose $result.Content
}
Else {
    $errorResponse = $result.Content | ConvertFrom-Json -Depth 99
    Write-Error "Policy update failed with error:`n$($errorResponse.error.code): $($errorResponse.error.message)"
}






