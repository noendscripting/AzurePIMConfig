ISO 8601 Duration Format

# PnYnMnDTnHnMnS

^P                       # Duration start with 'P'
(?:(\d+)Y)?               # Match optional years
(?:(\d+)M)?               # Match optional months
(?:(\d+)W)?               # Match optional weeks
(?:(\d+)D)?               # Match optional days
(?:T                       # Time separator
(?:(\d+)H)?               # Match optional hours
(?:(\d+)M)?               # Match optional minutes
(?:(\d+(?:\.\d+)?)S)?     # Match optional seconds, including fractional seconds
)?                        # End time section
$


'^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$'







#region Assigniment Settings 

#Setting Role Assignment Rules
$Expiration_Admin_Eligibility = [Expiration]::New()
$Expiration_Admin_Eligibility.isExpirationRequired = $false
$Expiration_Admin_Eligibility.target.level = 'Eligibility'
$Expiration_Admin_Eligibility.id = "Expiration_Admin_Eligibility"
$Expiration_Admin_Eligibility.maximumDuration = ""
$Expiration_Admin_Eligibility.ruleType = $ruleType.RoleManagementPolicyExpirationRule
$Expiration_Admin_Eligibility.target.caller = $caller.Admin

#Setting role assigniment expiration rules
$Expiration_Admin_Assignment = [Expiration]::New()
$Expiration_Admin_Assignment.isExpirationRequired = $true
$Expiration_Admin_Assignment.id = "Expiration_Admin_Assignment"
$Expiration_Admin_Assignment.maximumDuration = "P180D"
$Expiration_Admin_Assignment.ruleType = $ruleType.RoleManagementPolicyExpirationRule
$Expiration_Admin_Assignment.target.level = "Assignment"
$Expiration_Admin_Assignment.target.caller = $caller.Admin

#setting active role  assigniment settings (justification or\and MFA)
$Enablement_Admin_Assignment = [Enablement]::New()
$Enablement_Admin_Assignment.enabledRules = @("Justification")
$Enablement_Admin_Assignment.id = "Enablement_Admin_Assignment"
$Enablement_Admin_Assignment.ruleType = "RoleManagementPolicyEnablementRule"
$Enablement_Admin_Assignment.target.level = "Assignment"
$Enablement_Admin_Assignment.target.caller = $caller.Admin




#endregion

 
#region Setting Activation Rules

#set role duration settings
$Expiration_EndUser_Assignment = [Expiration]::New()
$Expiration_EndUser_Assignment.id = "Expiration_EndUser_Assignment"
$Expiration_EndUser_Assignment.ruleType = "RoleManagementPolicyExpirationRule"
$Expiration_EndUser_Assignment.maximumDuration = "PT240H"
$Expiration_EndUser_Assignment.isExpirationRequired = $true
$Expiration_EndUser_Assignment.target.level = "Assignment"
$Expiration_EndUser_Assignment.target.caller = $caller.Enduser

#set role activation requirments other than approval
$Enablement_EndUser_Assignment = [Enablement]::New()
$Enablement_EndUser_Assignment.enabledRules = @("Justification")
$Enablement_EndUser_Assignment.id = "Enablement_EndUser_Assignment"
$Enablement_EndUser_Assignment.ruleType = "RoleManagementPolicyEnablementRule"
$Enablement_EndUser_Assignment.target.level = "Assignment"
$Enablement_EndUser_Assignment.target.caller = $caller.Admin

#set role activation approval requiements 
$Approval_EndUser_Assignment = [Approval]::New()
$AprrovalStage = [approvalStage]::New()
$Approval_EndUser_Assignment.setting.approvalStages += $AprrovalStage
$Approval_EndUser_Assignment.setting.isApprovalRequired = $true
$Approval_EndUser_Assignment.id = "Approval_EndUser_Assignment"
$Approval_EndUser_Assignment.ruletype = $ruleType.RoleManagementPolicyApprovalRule 
$Approval_EndUser_Assignment.target.level = "Assigniment"
$Approval_EndUser_Assignment.target.caller = $caller.Enduser

#set approvers for the role
[Approver]$Approver1 = [Approver]::New()
$Approver1.description = "GiveMeAccess"
$Approver1.id = "c72990ad-8cf9-45dd-ab9a-016d2dd88c67"
$Approver1.isBackup = $false
$Approver1.userType = "Group"

[Approver]$Approver2 = [Approver]::New()
$Approver2.description = "Beth F. Woodard"
$Approver2.id = "82b18233-7541-4789-a139-f8221174ebb8"
$Approver2.isBackup = $false
$Approver2.userType = "User"

$AprrovalStage.primaryApprovers += $Approver1
$AprrovalStage.primaryApprovers += $Approver2
#endregion

#region notifications when members are assigned as eligible to this role

#Role assignment alert
$Notification_Admin_Admin_Eligibility = [Notification]::New()
$Notification_Admin_Admin_Eligibility.id = "Notification_Admin_Admin_Eligibility"
$Notification_Admin_Admin_Eligibility.ruleType = $ruleType.RoleManagementPolicyNotificationRule
$Notification_Admin_Admin_Eligibility.isDefaultRecipientsEnabled = $true
$Notification_Admin_Admin_Eligibility.notificationLevel = "All"
$Notification_Admin_Admin_Eligibility.notificationRecipients = @()
$Notification_Admin_Admin_Eligibility.recipientType = "Admin"
$Notification_Admin_Admin_Eligibility.target.caller = $caller.Admin
$Notification_Admin_Admin_Eligibility.target.level = "Assignment"

#set notifications for assigned user(assignee) 
$Notification_Requestor_Admin_Eligibility = [Notification]::New()
$Notification_Requestor_Admin_Eligibility.id = 'Notification_Requestor_Admin_Eligibility'
$Notification_Requestor_Admin_Eligibility.ruleType = $ruleType.RoleManagementPolicyNotificationRule
$Notification_Requestor_Admin_Eligibility.notificationLevel = "All"
$Notification_Requestor_Admin_Eligibility.isDefaultRecipientsEnabled = $true
$Notification_Requestor_Admin_Eligibility.recipientType = "Requestor"
$Notification_Requestor_Admin_Eligibility.notificationRecipients = @()
$Notification_Requestor_Admin_Eligibility.target.caller = $caller.Admin
$Notification_Requestor_Admin_Eligibility.target.level = "Assignment"

#set Request to approve a role assignment renewal/extension
$Notification_Approver_Admin_Eligibility = [Notification]::New()
$Notification_Approver_Admin_Eligibility.id = 'Notification_Approver_Admin_Eligibility'
$Notification_Approver_Admin_Eligibility.ruleType = $ruleType.RoleManagementPolicyNotificationRule
$Notification_Approver_Admin_Eligibility.notificationLevel = "All"
$Notification_Approver_Admin_Eligibility.notificationRecipients = @()
$Notification_Approver_Admin_Eligibility.isDefaultRecipientsEnabled = $true
$Notification_Approver_Admin_Eligibility.recipientType = "Approver"
$Notification_Approver_Admin_Eligibility.target.caller = $caller.Enduser
$Notification_Approver_Admin_Eligibility.target.level = "Assignment"

#endregion

#region notifications when members are assigned as active to this role

#Role assignment alert
$Notification_Admin_Admin_Assignment = [Notification]::New()
$Notification_Admin_Admin_Assignment.id = 'Notification_Admin_Admin_Assignment'
$Notification_Admin_Admin_Assignment.ruleType = $ruleType.RoleManagementPolicyNotificationRule
$Notification_Admin_Admin_Assignment.isDefaultRecipientsEnabled = $true
$Notification_Admin_Admin_Assignment.notificationLevel = "All"
$Notification_Admin_Admin_Assignment.notificationRecipients = @("notifyme@send.com")
$Notification_Admin_Admin_Assignment.recipientType = "Admin"
$Notification_Admin_Admin_Assignment.target.caller = $caller.Admin
$Notification_Admin_Admin_Assignment.target.level = "Assignment" 

#Notification to the assigned user (assignee)
$Notification_Requestor_Admin_Assignment = [Notification]::New()
$Notification_Requestor_Admin_Assignment.id = 'Notification_Requestor_Admin_Assignment'
$Notification_Requestor_Admin_Assignment.ruleType = $ruleType.RoleManagementPolicyNotificationRule
$Notification_Requestor_Admin_Assignment.isDefaultRecipientsEnabled = $true
$Notification_Requestor_Admin_Assignment.notificationLevel = "All"
$Notification_Requestor_Admin_Assignment.notificationRecipients = @()
$Notification_Requestor_Admin_Assignment.recipientType = "Requestor"
$Notification_Requestor_Admin_Assignment.target.caller = $caller.Admin
$Notification_Requestor_Admin_Assignment.target.level = "Assignment" 

#Request to approve a role assignment renewal/extension
$Notification_Approver_Admin_Assignment = [Notification]::New()
$Notification_Approver_Admin_Assignment.id = 'Notification_Approver_Admin_Assignment'
$Notification_Approver_Admin_Assignment.ruleType = $ruleType.RoleManagementPolicyNotificationRule
$Notification_Approver_Admin_Assignment.isDefaultRecipientsEnabled = $true
$Notification_Approver_Admin_Assignment.notificationLevel = "All"
$Notification_Approver_Admin_Assignment.notificationRecipients = @()
$Notification_Approver_Admin_Assignment.recipientType = "Approver"
$Notification_Approver_Admin_Assignment.target.caller = $caller.Admin
$Notification_Approver_Admin_Assignment.target.level = "Assignment"

#endregion

#region notifications when eligible members activate this role

#Role activation alert
$Notification_Admin_EndUser_Assignment = [Notification]::New()
$Notification_Admin_EndUser_Assignment.id = 'Notification_Admin_EndUser_Assignment'
$Notification_Admin_EndUser_Assignment.ruleType = $ruleType.RoleManagementPolicyNotificationRule
$Notification_Admin_EndUser_Assignment.isDefaultRecipientsEnabled = $true
$Notification_Admin_EndUser_Assignment.notificationLevel = "All"
$Notification_Admin_EndUser_Assignment.notificationRecipients = @()
$Notification_Admin_EndUser_Assignment.recipientType = "Admin"
$Notification_Admin_EndUser_Assignment.target.caller = $caller.Enduser
$Notification_Admin_EndUser_Assignment.target.level = "Assignment"

#set Notification to activated user (requestor)
$Notification_Requestor_EndUser_Assignment = [Notification]::New()
$Notification_Requestor_EndUser_Assignment.id = 'Notification_Requestor_EndUser_Assignment'
$Notification_Requestor_EndUser_Assignment.ruleType = $ruleType.RoleManagementPolicyNotificationRule
$Notification_Requestor_EndUser_Assignment.notificationLevel = "All"
$Notification_Requestor_EndUser_Assignment.notificationRecipients = @()
$Notification_Requestor_EndUser_Assignment.isDefaultRecipientsEnabled = $true
$Notification_Requestor_EndUser_Assignment.recipientType = "Requestor"
$Notification_Requestor_EndUser_Assignment.target.caller = $caller.Enduser
$Notification_Requestor_EndUser_Assignment.target.level = "Assignment"

#Request to approve an activation
$Notification_Approver_EndUser_Assignment = [Notification]::New()
$Notification_Approver_EndUser_Assignment.id = 'Notification_Approver_EndUser_Assignment'
$Notification_Approver_EndUser_Assignment.ruleType = $ruleType.RoleManagementPolicyNotificationRule
$Notification_Approver_EndUser_Assignment.isDefaultRecipientsEnabled = $true
$Notification_Approver_EndUser_Assignment.notificationLevel = "All"
$Notification_Approver_EndUser_Assignment.notificationRecipients = @() # must be empty array at all time
$Notification_Approver_EndUser_Assignment.recipientType = "Approver"
$Notification_Approver_EndUser_Assignment.target.caller = $caller.Enduser
$Notification_Approver_EndUser_Assignment.target.level = "Assignment" 


#endregion

#set 





#Role activation alert






#region Creating rules array

$policySettings = @()


<#$policySettings += $Expiration_Admin_Eligibility
$policySettings += $Enablement_EndUser_Assignment
$policySettings += $Expiration_EndUser_Assignment
$policySettings += $Approval_EndUser_Assignment
$policySettings += $Notification_Requestor_Admin_Eligibility #
$policySettings += $Notification_Requestor_EndUser_Assignment
$policySettings += $Notification_Approver_Admin_Eligibility #
$policySettings += $Notification_Approver_Admin_Assignment
$policySettings += $Notification_Admin_EndUser_Assignment
$policySettings += $Notification_Approver_EndUser_Assignment
$policySettings += $Notification_Requestor_Admin_Assignment
$policySettings += $Notification_Admin_Admin_Eligibility #
$policySettings += $Notification_Admin_Admin_Assignment
$policySettings += $Expiration_Admin_Assignment
$policySettings += $Enablement_Admin_Assignment
#>
$policyObject.properties.rules = $policySettings
#endregion

#region update policy 
$policyUpdate = $policyObject | ConvertTo-Json -Depth 99




Write-Verbose $policyUpdate
Invoke-AzRest -Path "$($resourceId)/providers/Microsoft.Authorization/roleManagementPolicies/$($policyName)?api-version=$($apiVersion)" -Method PATCH -Payload $policyUpdate

#endregion