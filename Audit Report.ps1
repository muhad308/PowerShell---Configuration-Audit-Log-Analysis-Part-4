$auditFolderPath = "./network_configs"
$outputFile = "security_audit.txt"

$allFiles = Get-ChildItem -Path $auditFolderPath -Recurse -File |
Where-Object { $_.Extension -in ".conf", ".rules", ".bak", ".log" }

$configCount = ($allFiles | Where-Object { $_.Extension -eq ".conf" }).Count
$logCount = ($allFiles | Where-Object { $_.Extension -eq ".log" }).Count
$rulesCount = ($allFiles | Where-Object { $_.Extension -eq ".rules" }).Count
$bakCount = ($allFiles | Where-Object { $_.Extension -eq ".bak" }).Count
$totalCount = $allFiles.Count

$now = Get-Date "2024-10-14"
$weekAgo = $now.AddDays(-7)

$lastWeekFiles = Get-ChildItem -Path $auditFolderPath -Recurse -File |
Where-Object { $_.LastWriteTime -gt $weekAgo } |
Sort-Object LastWriteTime -Descending

$timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$report = @"
===============================================================================
                    SECURITY AUDIT REPORT - TechCorp AB
===============================================================================

Generated: $timeStamp
Audit Path: $auditFolderPath


FILE INVENTORY
--------------

Total Files:     $totalCount
Config Files:    $configCount
Log Files:       $logCount
Rule Files:      $rulesCount
Backup Files:    $bakCount

Files Modified Last 7 Days: $($lastWeekFiles.Count)
"@

foreach ($file in $lastWeekFiles) {
  $report += "`n- $($file.Name) ($($file.LastWriteTime.ToString('yyyy-MM-dd')))"
}

$passwordIssues = @()
$snmpIssues = @()

$confFiles = Get-ChildItem -Path $auditFolderPath -Recurse -File -Filter *.conf

foreach ($file in $confFiles) {
  $lines = Get-Content $file.FullName
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $lineNum = $i + 1

    if ($line -match "enable password|secret") {
      $passwordIssues += "   - $($file.Name): `"$line`" (line $lineNum)"
    }

    if ($line -match "\b(public|private)\b") {
      $snmpIssues += "   - $($file.Name): `"$line`" (line $lineNum)"
    }
  }
}

$encryptionIssues = @()
$rulesFiles = Get-ChildItem -Path $auditFolderPath -Recurse -File -Filter *.rules

foreach ($file in $rulesFiles) {
  $lines = Get-Content $file.FullName
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $lineNum = $i + 1

    if ($line -match "\bAllow HTTP\b|Unencrypted") {
      $encryptionIssues += "   - $($file.Name): `"$line`" (line $lineNum)"
    }
  }
}

$totalFindings = $passwordIssues.Count + $snmpIssues.Count + $encryptionIssues.Count

$report += "`n`nSECURITY FINDINGS`n-----------------`n"
$report += "`nCritical Issues Found: $totalFindings`n"

if ($passwordIssues.Count -gt 0) {
  $report += "`n. Weak Passwords Detected:`n" + ($passwordIssues -join "`n")
}
if ($snmpIssues.Count -gt 0) {
  $report += "`n`n. Default SNMP Communities:`n" + ($snmpIssues -join "`n")
}
if ($encryptionIssues.Count -gt 0) {
  $report += "`n`n. Missing Encryption:`n" + ($encryptionIssues -join "`n")
}


# Log analysis
$last24Hours = $now.AddHours(-24)
$logSummary = @()
$failedAttempts = @{}

$logFiles = Get-ChildItem -Path $auditFolderPath -Recurse -File -Filter *.log
$totalErrors = 0
$totalFailedLogins = 0

foreach ($log in $logFiles) {
  $lines = Get-Content $log.FullName
  $recentLines = $lines | Where-Object {
    ($_ -match "\d{4}-\d{2}-\d{2}") -and
    ([datetime]($_.Substring(0, 10))) -gt $last24Hours
  }

  $errorCount = ($recentLines | Select-String "ERROR").Count
  if ($errorCount -gt 0) {
    $logSummary += "- $($log.Name): $errorCount errors"
    $totalErrors += $errorCount
  }

  $failedMatches = $recentLines | Select-String "LOGIN FAILED"
  foreach ($match in $failedMatches) {
    $totalFailedLogins++
    if ($match.Line -match "\d{1,3}(\.\d{1,3}){3}") {
      $ip = ($match.Line -match "\d{1,3}(\.\d{1,3}){3}") | Out-Null
      $ip = $match.Line -replace ".*?(\d{1,3}(\.\d{1,3}){3}).*", '$1'
      if ($failedAttempts.ContainsKey($ip)) {
        $failedAttempts[$ip]++
      }
      else {
        $failedAttempts[$ip] = 1
      }
    }
  }
}

$logReport = @"
LOG ANALYSIS
------------

Errors in Last 24 Hours: $totalErrors`n
"@ + ($logSummary -join "`n") + "`n`n"

$logReport += "Failed Login Attempts: $totalFailedLogins`n"

foreach ($ip in $failedAttempts.Keys) {
  $logReport += "- $($failedAttempts[$ip]) attempts from $ip`n"
}

$report += "`n`n$logReport"

$missingBackups = @()
$sevenDaysAgo = $now.AddDays(-7)

$confAndRuleFiles = Get-ChildItem -Path $auditFolderPath -Recurse -File |
Where-Object { $_.Extension -in ".conf", ".rules" }

$bakFiles = Get-ChildItem -Path $auditFolderPath -Recurse -File -Filter *.bak

foreach ($target in $confAndRuleFiles) {
  $expectedBakName = "$($target.Name).bak"
  $matchingBak = $bakFiles | Where-Object {
    $_.Name -eq $expectedBakName
  }
    
  if ($matchingBak.Count -eq 0) {
    $missingBackups += "- $($target.Name) (no backup found)"
  }
  else {
    $bakFile = $matchingBak | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($bakFile.LastWriteTime -gt $sevenDaysAgo) {
      $dateStr = $bakFile.LastWriteTime.ToString("yyyy-MM-dd")
      $missingBackups += "- $($target.Name) (last backup: $dateStr)"
    }
  }
}

if ($missingBackups.Count -gt 0) {
  $report += "`n`nMISSING BACKUPS`n---------------`n"
  $report += "`nFiles without recent backup (>7 days):`n"
  $report += ($missingBackups -join "`n")
}

$baselinePath = "$($auditFolderPath)/baseline/baseline-router.conf"
$routerPath = "$($auditFolderPath)/routers"

$complianceLines = @()
$inBannerBlock = $false

foreach ($line in Get-Content $baselinePath) {
  $trimmed = $line.Trim()
   
  if ($trimmed -match "\s+\w+\s+\^C$") {
    $inBannerBlock = $true
    continue
  }

  if ($inBannerBlock -and $trimmed -eq "^C") {
    $inBannerBlock = $false
    continue
  }

  if (
    $inBannerBlock -or
    $trimmed -eq "" -or
    $trimmed.StartsWith("!") -or
    $trimmed.ToLower().StartsWith("logging")
  ) {
    continue
  }

  $complianceLines += $trimmed
}


$complianceMissingResults = @()

$routerConfigs = Get-ChildItem -Path $routerPath -Filter *.conf

foreach ($router in $routerConfigs) {
  $routerLines = Get-Content $router.FullName
  $missingLines = @()

  foreach ($complianceLine in $complianceLines) {
    if (-not ($routerLines -contains $complianceLine)) {
      $missingLines += $complianceLine
    }
  }

  foreach ($missing in $missingLines) {
    $complianceMissingResults += "- $($router.Name): Missing `"$missing`""
  }
}

if ($complianceMissingResults.Count -gt 0) {
  $report += "`n`nBASELINE COMPLIANCE`n-------------------`n"
  $report += "`nDeviations from baseline-router.conf:`n"
  $report += ($complianceMissingResults -join "`n")
}


$report | Out-File -FilePath $outputFile -Encoding UTF8

$outputCsv = "config_inventory.csv"

$configFiles = Get-ChildItem -Path $rootPath -Recurse -File -Filter *.conf |
Where-Object {
  $folder = Split-Path $_.DirectoryName -Leaf
  $folder -in @("switches", "firewalls", "routers")
}


$bakFiles = Get-ChildItem -Path $auditFolderPath -Recurse -File -Filter *.bak


$inventory = @()

foreach ($file in $configFiles) {
  $fileName = $file.Name
  $fullPath = $file.FullName
  $sizeKB = [math]::Round($file.Length / 1KB, 1)
  $lastModified = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")

  $folder = Split-Path $file.DirectoryName -Leaf
  switch ($folder.ToLower()) {
    "routers" { $fileType = "router" }
    "switches" { $fileType = "switch" }
    "firewalls" { $fileType = "firewall" }
    default { $fileType = "unknown" }
  }
    
  $expectedBak = "$fileName.bak"
  $hasBackup = $bakFiles | Where-Object { $_.Name -eq $expectedBak }
  $hasBackupFlag = if ($hasBackup) { "True" } else { "False" }

  $inventory += [PSCustomObject]@{
    FileName     = $fileName
    FullPath     = $fullPath
    SizeKB       = $sizeKB
    LastModified = $lastModified
    FileType     = $fileType
    HasBackup    = $hasBackupFlag
  }
}

$inventory | Export-Csv -Path $outputCsv -NoTypeInformation -Encoding UTF8