<#
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
#> 
 
 
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$role = "Contributor",
    [string]$resourceId = "/subscriptions/87008fdf-ae91-4584-b623-7ecb86459002/resourceGroups/AADBkup-RG/providers/Microsoft.Storage/storageAccounts/aadbkup",
    [string]$apiVersion = '2020-10-01'
)
  
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

#$ErrorActionPreference = 'Stop'


#region Classes

$classInstanceTable = @{
    "Activation maximum duration (hours)"                             = "Expiration_EndUser_Assignment"
    "On activation, require"                                          = "Enablement_EndUser_Assignment"
    "Require approval to activate"                                    = "Approval_EndUser_Assignment"
    "Allow permanent eligible assignment"                             = "Expiration_Admin_Eligibility"
    "Allow permanent active assignment"                               = "Expiration_Admin_Assignment"
    "On active assignment, require"                                   = "Enablement_Admin_Assignment"
    "Role assignment alert eligible"                                  = "Notification_Admin_Admin_Eligibility"
    "Notification to the assigned user (assignee) eligible"           = "Notification_Requestor_Admin_Eligibility"
    "Request to approve a role assignment renewal/extension eligible" = "Notification_Approver_Admin_Eligibility"
    "Role assignment alert active"                                    = "Notification_Admin_Admin_Assignment"
    "Notification to the assigned user (assignee) active"             = "Notification_Requestor_Admin_Assignment"
    "Request to approve a role assignment renewal/extension active"   = "Notification_Approver_Admin_Assignment"
    "Role activation alert"                                           = "Notification_Admin_EndUser_Assignment"
    "Notification to activated user (requestor)"                      = "Notification_Requestor_EndUser_Assignment"
"Request to approve an activation"                                = "Notification_Approver_EndUser_Assignment"
}






Class Approver {
    [string]$id
    [string]$description
    [string]$isBackup
    [ValidateSet('Group', 'User')]
    [string]$userType
}

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

#endregion
$roleDefenitionId = (Get-AzRoleDefinition -Name $role -Scope $resourceId).Id
Write-Verbose $roleDefenitionId
$filter = '$filter'
#region collect and backup current policy settings

$policyResult = (Invoke-AzRest -Path "$($resourceId)/providers/Microsoft.Authorization/roleManagementPolicies?api-version=$($apiVersion)&$filter=roleDefinitionId%20eq%20'$($resourceId)/providers/Microsoft.Authorization/roleDefinitions/$($roleDefenitionId)'" -Method GET).Content
#backup current policy 
$policyResult | Out-File ./policyResult.json -Force
$policyName = ($policyResult | ConvertFrom-Json).value.name



#region create root policy object and rules array
$policyObject = [PolicySettings]::New()
$policySettings = @()
#endregion


$configData = Get-Content .\answer.json | ConvertFrom-Json -Depth 99

forEach ($ruleEntry in $configData.rules) {
    switch ($ruleEntry.ruleName) {
        "Activation maximum duration (hours)" {
            $expiration = [Expiration]::New()
            $expiration.isExpirationRequired = $true
            $expiration.maximumDuration = $ruleEntry.maximumDuration
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
            $expiration.maximumDuration = $ruleEntry.maximumDuration
            $expiration.id = "Expiration_Admin_Eligibility"
            $expiration.target.caller = "Admin"
            $expiration.target.level = "Eligibility"
            $policySettings += $expiration
        }
       "Allow permanent active assignment" {
            $expiration = [Expiration]::New()
            $expiration.isExpirationRequired = $ruleEntry.isExpirationRequired
            $expiration.maximumDuration = $ruleEntry.maximumDuration
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
$policyObject.properties.rules = $policySettings
$policyUpdate = $policyObject | ConvertTo-Json -Depth 99
Write-Verbose $policyUpdate

Invoke-AzRest -Path "$($resourceId)/providers/Microsoft.Authorization/roleManagementPolicies/$($policyName)?api-version=$($apiVersion)" -Method PATCH -Payload $policyUpdate





