[CmdletBinding()]

param(
   <# [string]$RoleActivationMaximumDuration,
    [bool]$RequireJustificationOnRoleActivation,
    [bool]$RequireTicketInformationOnRoleActivation,
    [bool]$RequireApprovalToActivateRole,
    [string[]]$RoleActivationApprovers,
    [Parameter(Mandatory)]
    [string]$role,
    [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
    [string]$Id
    #>

)


# regex for dateInterval format  '(P([1-9]|[1-9][0-9])(W|D|M|H)|PT([1-9]|[1-9][0-9])H)'
<#
    5 RULES
    unifiedRoleManagementPolicyApprovalRule
     {   "id": "Approval_EndUser_Assignment",
        "ruleType": "RoleManagementPolicyApprovalRule",
        "target": {
          "caller": "EndUser",
          "operations": [
            "All"
          ],
          "level": "Assignment",
          "targetObjects": null,
          "inheritableSettings": null,
          "enforcedSettings": null
        }
        "setting": {
                "isApprovalRequired": false,
                "isApprovalRequiredForExtension": false,
                "isRequestorJustificationRequired": true,
                "approvalMode": "SingleStage",
                "approvalStages": [
                    {
                        "approvalStageTimeOutInDays": 1,
                        "isApproverJustificationRequired": true,
                        "escalationTimeInMinutes": 0,
                        "isEscalationEnabled": false,
                        "primaryApprovers": [],
                        "escalationApprovers": []
                    }
                ]
            }
      }

    unifiedRoleManagementPolicyAuthenticationContextRule                {
           
    unifiedRoleManagementPolicyEnablementRule
    Eligibility
    {
        "enabledRules": [],
        "id": "Enablement_Admin_Eligibility",
        "ruleType": "RoleManagementPolicyEnablementRule",
        "target": {
          "caller": "Admin",
          "operations": [
            "All"
          ],
          "level": "Eligibility",
          "targetObjects": null,
          "inheritableSettings": null,
          "enforcedSettings": null
        }
    }
    Assigniment
    { 
     "enabledRules": [
              "MultiFactorAuthentication",
              "Justification",
              "Ticketing"
            ],
            "id": "Enablement_EndUser_Assignment",
            "ruleType": "RoleManagementPolicyEnablementRule",
            "target": {
              "caller": "EndUser",
              "operations": [
                "All"
              ],
              "level": "Assignment",
              "targetObjects": null,
              "inheritableSettings": null,
              "enforcedSettings": null
            }
     }
          

          
  unifiedRoleManagementPolicyExpirationRule
    Eligibility
       {
        "isExpirationRequired": true,
        "maximumDuration": "P90D",
        "id": "Expiration_Admin_Eligibility",
        "ruleType": "RoleManagementPolicyExpirationRule",
        "target": {
          "caller": "Admin",
          "operations": [
            "All"
          ],
          "level": "Eligibility",
          "targetObjects": null,
          "inheritableSettings": null,
          "enforcedSettings": null
        }
      }
    Assigniment
    {
        "isExpirationRequired": false,
        "maximumDuration": "P90D",
        "id": "Expiration_Admin_Assignment",
        "ruleType": "RoleManagementPolicyExpirationRule",
        "target": {
          "caller": "Admin",
          "operations": [
            "All"
          ],
          "level": "Assignment",
          "targetObjects": null,
          "inheritableSettings": null,
          "enforcedSettings": null
        }
      } 
    unifiedRoleManagementPolicyNotificationRule

    {
            "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule",
            "id": "Notification_Admin_Admin_Eligibility",
            "notificationType": "Email",
            "recipientType": "Admin",
            "notificationLevel": "All",
            "isDefaultRecipientsEnabled": true,
            "notificationRecipients": [],
            "target": {
                "caller": "Admin",
                "operations": [
                    "all"
                ],
                "level": "Eligibility",
                "inheritableSettings": [],
                "enforcedSettings": []
            }
        },
        {
            "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule",
            "id": "Notification_Requestor_Admin_Eligibility",
            "notificationType": "Email",
            "recipientType": "Requestor",
            "notificationLevel": "All",
            "isDefaultRecipientsEnabled": true,
            "notificationRecipients": [],
            "target": {
                "caller": "Admin",
                "operations": [
                    "all"
                ],
                "level": "Eligibility",
                "inheritableSettings": [],
                "enforcedSettings": []
            }
        },
        {
            "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule",
            "id": "Notification_Approver_Admin_Eligibility",
            "notificationType": "Email",
            "recipientType": "Approver",
            "notificationLevel": "All",
            "isDefaultRecipientsEnabled": true,
            "notificationRecipients": [],
            "target": {
                "caller": "Admin",
                "operations": [
                    "all"
                ],
                "level": "Eligibility",
                "inheritableSettings": [],
                "enforcedSettings": []
            }
        },



Properties
Caller
Operations
level
inhetitableSettings
enforcedSettings

#>


#region Classes

#class for policy settings array 
class PolicyProperties
{
        [array]$rules 
}

#root class for PIM polciies 
class PolicySettings
{
        [PolicyProperties]$properties=[PolicyProperties]::New()
}

#class to define target object
<#class Target
{
    [string]$caller = "EndUser" # posisble values EndUser, Admin
    [string[]]$operations = @("All")
    [string]$level # Possible values Elibility, Assignmnet 
   # [object]$targetObjects = $null
   # [object]$enforcedSettings= $null
   # [object]$inheritableSettings=$null
}#>

class Target
{
    [string]$caller = "EndUser"
    [string[]]$operations = @("All")
    [string]$level
    [object]$targetObjects = $null
    [object]$enforcedSettings= $null
    [object]$inheritableSettings=$null
}

<#Class Expiration
    {
        [bool]$isExpirationRequired
        [string]$maximumDuration
        [string]$id
        [string]$ruleType
        [Target]$target = [Target]::New()
    }#>

    Class Expiration
    {
        [bool]$isExpirationRequired
        [string]$maximumDuration
        [string]$id ="Expiration_EndUser_Assignment"
        [string]$ruleType = "RoleManagementPolicyExpirationRule"
        [Target]$target = [Target]::New()
    }

    Class Expiration_EndUser_Assignment
{
    [bool]$isExpirationRequired
    [string]$maximumDuration
    [string]$id ="Expiration_EndUser_Assignment"
    [string]$ruleType = "RoleManagementPolicyExpirationRule"
    [Target]$target = [Target]::New()
}
Class Enablement 
{
  
    [string[]]$enabledRules = @() # possible values "MultiFactorAuthentication", "Justification","Ticketing"
    [string]$id 
    [string]$ruleType
    [Target]$target = [Target]::New()

}
#end region




$id = "/subscriptions/87008fdf-ae91-4584-b623-7ecb86459002/resourceGroups/AADBkup-RG/providers/Microsoft.Storage/storageAccounts/aadbkup"
$role = "Contributor"
$apiVersion='2020-10-01'
$roleDefenitionId = (Get-AzRoleDefinition -Name $role -Scope $Id).Id
Write-Verbose $roleDefenitionId
$filter = '$filter'
#region collect current policy settings
$policyResult = (Invoke-AzRest -Path "$($Id)/providers/Microsoft.Authorization/roleManagementPolicies?api-version=2020-10-01-preview&$($filter)=roleDefinitionId%20eq%20'$($Id)/providers/Microsoft.Authorization/roleDefinitions/$($roleDefenitionId)'" -Method GET).Content # | ConvertFrom-Json
#backup current policy 


$policyObject = [PolicySettings]::New()
#region Setting Role Assignment Rules
<#$Expiration_Admin_Eligibility = [Expiration_Admin_Eligibility]::New()
$Expiration_Admin_Eligibility.isExpirationRequired = $false
$Expiration_Admin_Eligibility.target.level = 'Eligibility'

$Enablement_EndUser_Assignment = [Enablement_EndUser_Assignment]::New()
$Enablement_EndUser_Assignment.enabledRules = @("Justification","MultiFactorAuthentication")
$Enablement_EndUser_Assignment.target.level = 'Assignment'#>
#endregion
#region Setting Activation Rules
$Expiration_EndUser_Assignment = [Expiration_EndUser_Assignment]::New()
$Expiration_EndUser_Assignment.maximumDuration = "PT600H"
$Expiration_EndUser_Assignment.isExpirationRequired = $true
$Expiration_EndUser_Assignment.target.level = 'Assignment'
#endregion

#region Creating rules array
$policySettings = @()

#$policySettings += $Expiration_Admin_Eligibility
#$policySettings += $Enablement_EndUser_Assignment
$policySettings += $Expiration_EndUser_Assignment

$policyObject.properties.rules = $policySettings
#endregion
#endregion

$policySettings = @()

$policySettings += $Expiration_EndUser_Assignment
#$policySettings += $Enablement_EndUser_Assignment

$policyObject.properties.rules = $policySettings
$policyObject.properties.rules

#region update policy 
$policyUpdate = $policyObject | ConvertTo-Json -Depth 99
Write-Verbose $policyUpdate
Invoke-AzRest -Path "$($resourceId)/providers/Microsoft.Authorization/roleManagementPolicies/$($policyName)?api-version=$($apiVersion)" -Method PATCH -Payload $policyUpdate -Debug
#endregion