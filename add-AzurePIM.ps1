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


[cmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$groupName,
    [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
    [string]$Id,
    [Parameter(Mandatory)]
    [string]$role,
    [string]$apiVersion = '2020-10-01'
)

#region Classes
class EligibilityAssignment
{
  [EligibilityAssignmentPropeties]$properties=[EligibilityAssignmentPropeties]::New()
}
class EligibilityAssignmentPropeties
    {
        [string]$roleDefinitionId
        [string]$principalId
        [string]$requestType = 'AdminAssign'
        [ScheduleInfo]$ScheduleInfo = [ScheduleInfo]::New()
        
    }
class ScheduleInfo {
    [string]$StartDateTime # format "2020-09-09T21:31:27.91Z"
    [Expiration]$Expiration = [Expiration]::New()
  }
  class Expiration {
    [string]$Type = 'NoExpiration'  # Values: AfterDuration, AfterDateTime, NoExpiration
    [string]$EndDateTime
    [string]$Duration  #"P365D"  Use ISO 8601 format
  }
#endrgeion


Write-Debug $Id
$filter = '$filter'
$select = '$select'


write-host "https://graph.microsoft.com/v1.0/groups?$($filter)=startswith(displayName,'$groupName')&$($select)=id"


$groupData = (Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/groups?$($filter)=startswith(displayName,'$groupName')&$($select)=id").Content | ConvertFrom-Json -Depth 99
$groupObjectId = $groupData.value.id
$roleEligibilityScheduleRequestName = (new-guid).Guid
$roleDefenitionId = (Get-AzRoleDefinition -Name $role -Scope $Id).Id
$subscriptionId = $Id.Split("/")[2]


$eligibilityScheduleObject = [EligibilityAssignment]::New()


$eligibilityScheduleObject.properties.PrincipalId = $groupObjectId
$eligibilityScheduleObject.properties.RoleDefinitionId="/subscriptions/$($subscriptionId)/providers/Microsoft.Authorization/roleDefinitions/$($roleDefenitionId)"
$assignmentPayload = $eligibilityScheduleObject | ConvertTo-Json -Depth 99

Invoke-AzRest -Path "$($Id)/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/$($roleEligibilityScheduleRequestName)?api-version=$($apiVersion)" -Method PUT -Payload $assignmentPayload
