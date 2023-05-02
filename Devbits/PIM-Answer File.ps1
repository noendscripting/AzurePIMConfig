
[CmdletBinding()]

param()
$parserStack = New-Object System.Collections.Stack
#$configData = (select-String -Pattern '^-.|.-.' -Path .\test.yml -AllMatches).Line
$configData = Get-Content .\answer.json | ConvertFrom-Json -Depth 99
$configData.rules[2]





#collecting list of section names from answer file
$mymatches = $configData | Select-String -Pattern '^[\-].*' -AllMatches | Select-Object -Property Line,LineNumber


#lo
for ($classEntry = 0; $classEntry -lt $mymatches.Length; $classEntry++) {
    Write-Verbose "Starting values for $($mymatches[$classEntry].Line.Split(':')[1])"
#setting end of a
    if ($classEntry -eq ($mymatches.Length - 1)) {
        $endofClass = $configData.Length
    }
    else {
        $endofClass = ($mymatches[$classEntry + 1].LineNumber - 1)
    }
    for ($configEntry = $mymatches[$classEntry].LineNumber; $configEntry -lt $endofClass; $configEntry++) {
        if ($configData[$configEntry] -match '^ -') {
            [array]$objectProperties += $configData[$configEntry].Replace(" -", "")             
        }
    }

    $classId = $classInstanceTable[$mymatches[$classEntry].Line.Split(':')[1]]
    $classDetails = $classId.Split('_')
    $classType = $classDetails[0]
    $targetLevel = $classDetails[1]
    $targetCaller = $classDetails[2]


    Write-Verbose "Class Name: $($className) of ClassTYpe: $($classType)"

    $classObject = New-Object -TypeName $classType
    $classObject.id = $classId
    $classObject.target.level = $targetLevel
    $classObject.target.caller = $targetCaller


    ForEach ($settingsProperty in $objectProperties) {

      $propertyName = $settingsProperty.Split(":")[0]
      $propertyValue = $settingsProperty.Split(":")[1]
      if ($propertyName -eq 'approver')
      {
        $AprrovalStage = [approvalStage]::New()

      }
        $classObject | Add-Member -Name $propertyName -Value $propertyValue -Force -MemberType NoteProperty

    }

    $classObject
    $objectProperties
    Clear-Variable objectProperties
    Clear-Variable ClassType
    Clear-Variable classId
    Clear-Variable classObject

}





