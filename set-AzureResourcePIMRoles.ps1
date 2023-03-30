

$json = @'
{
        "enabledRules": [
            "Justification"
        ],
        "id": "Enablement_Admin_Assignment",
        "ruleType": "RoleManagementPolicyEnablementRule",
        "target": {
            "caller": "Admin",
            "operations": [
                "All"
            ],
            "level": "Assignment"
        }
    }
'@

$json | ConvertFrom-Json -Depth 99

$testHash = @{
    "enabledRules" = @()
    "id"           = "Enablement_Admin_Assignment"
    "ruleType"     = "RoleManagementPolicyEnablementRule"
    "target"       = @{
    }


}

$enabledrules = @("Justifictaion")

$testHash.enabledRules = $enabledrules
$testHash.target.add("caller","Admin")



$testHash | ConvertTo-Json -Compress -Depth 99