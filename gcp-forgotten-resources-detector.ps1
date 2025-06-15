# 🕵️ Forgotten Resource Detective for GCP (Enhanced)
# A simple script to find resources that might be forgotten and costing you money
# Part of the "FinOps for Everyone" series

param(
    [Parameter(Mandatory=$true)]
    [string]$ProjectId,
    
    [Parameter(Mandatory=$false)]
    [string]$Region = "",
    
    [Parameter(Mandatory=$false)]
    [int]$DaysThreshold = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "forgotten-resources-report.html",
    
    [Parameter(Mandatory=$false)]
    [string]$CsvOutputPath = "forgotten-resources-report.csv"
)

# 🚀 Initialize GCP CLI (make sure gcloud is configured)
Write-Host "Starting GCP Forgotten Resource Detective..." -ForegroundColor Cyan
Write-Host "Looking for resources older than $DaysThreshold days with suspicious patterns..." -ForegroundColor Yellow

# Set GCP project context
gcloud config set project $ProjectId

# Test GCP CLI connectivity
try {
    $projectInfo = gcloud config get-value project
    $accountInfo = gcloud config get-value account
    Write-Host "Connected to GCP Project: $projectInfo as $accountInfo" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to GCP. Please ensure gcloud CLI is configured with 'gcloud auth login'"
    exit 1
}

# 💾 Get detailed persistent disk information to identify orphans
Write-Host "Analyzing persistent disks..." -ForegroundColor Blue
$allDisks = gcloud compute disks list --format="json" | ConvertFrom-Json

# 🌐 Get detailed network information
Write-Host "Analyzing network resources..." -ForegroundColor Blue
$staticIPs = gcloud compute addresses list --format="json" | ConvertFrom-Json
$networkInterfaces = @() # Will be populated from instance data
$firewallRules = gcloud compute firewall-rules list --format="json" | ConvertFrom-Json

# ⚖️ Get load balancer information
Write-Host "Analyzing load balancers..." -ForegroundColor Blue
try {
    $urlMaps = gcloud compute url-maps list --format="json" | ConvertFrom-Json
    $backendServices = gcloud compute backend-services list --format="json" | ConvertFrom-Json
    $targetPools = gcloud compute target-pools list --format="json" | ConvertFrom-Json
    $forwardingRules = gcloud compute forwarding-rules list --format="json" | ConvertFrom-Json
} catch {
    $urlMaps = @()
    $backendServices = @()
    $targetPools = @()
    $forwardingRules = @()
    Write-Host "Some load balancer components not found or permission denied" -ForegroundColor Gray
}

# 🖥️ Get Compute Engine instance information
Write-Host "Analyzing Compute Engine instances..." -ForegroundColor Blue
$computeInstances = gcloud compute instances list --format="json" | ConvertFrom-Json

# 🗄️ Get Cloud Storage bucket information
Write-Host "Analyzing Cloud Storage buckets..." -ForegroundColor Blue
try {
    $gcsRawOutput = gcloud storage ls --json 2>$null
    if ($gcsRawOutput) {
        $gcsBuckets = $gcsRawOutput | ConvertFrom-Json
    } else {
        # Fallback to gsutil if gcloud storage is not available
        $bucketNames = gsutil ls 2>$null
        $gcsBuckets = @()
        foreach ($bucketUrl in $bucketNames) {
            if ($bucketUrl -match "gs://(.+)") {
                $bucketName = $matches[1].TrimEnd('/')
                $gcsBuckets += [PSCustomObject]@{
                    name = $bucketName
                    timeCreated = $null
                    labels = @{}
                }
            }
        }
    }
} catch {
    $gcsBuckets = @()
    Write-Host "Unable to list Cloud Storage buckets or permission denied" -ForegroundColor Gray
}

# 📸 Get snapshots and images
Write-Host "Analyzing snapshots and images..." -ForegroundColor Blue
$snapshots = gcloud compute snapshots list --format="json" | ConvertFrom-Json
$customImages = gcloud compute images list --no-standard-images --format="json" | ConvertFrom-Json

# 🔑 Get unused SSH keys and service accounts
Write-Host "Analyzing project metadata and service accounts..." -ForegroundColor Blue
try {
    $projectMetadata = gcloud compute project-info describe --format="json" | ConvertFrom-Json
    $serviceAccounts = gcloud iam service-accounts list --format="json" | ConvertFrom-Json
} catch {
    $projectMetadata = $null
    $serviceAccounts = @()
    Write-Host "Unable to fetch project metadata or service accounts" -ForegroundColor Gray
}

# 🌍 Get Cloud SQL instances
Write-Host "Analyzing Cloud SQL instances..." -ForegroundColor Blue
try {
    $sqlInstances = gcloud sql instances list --format="json" | ConvertFrom-Json
} catch {
    $sqlInstances = @()
    Write-Host "No Cloud SQL instances found or permission denied" -ForegroundColor Gray
}

# 🔥 Get Cloud Functions
Write-Host "Analyzing Cloud Functions..." -ForegroundColor Blue
try {
    if ($Region) {
        $cloudFunctions = gcloud functions list --regions=$Region --format="json" | ConvertFrom-Json
    } else {
        $cloudFunctions = gcloud functions list --format="json" | ConvertFrom-Json
    }
} catch {
    $cloudFunctions = @()
    Write-Host "No Cloud Functions found or permission denied" -ForegroundColor Gray
}

# Calculate current date for age calculations
$currentDate = Get-Date

# Identify orphaned persistent disks
$orphanedDisks = $allDisks | Where-Object { 
    $_.status -eq "READY" -and ($_.users -eq $null -or $_.users.Count -eq 0)
}

# Identify unattached static IPs
$unattachedStaticIPs = $staticIPs | Where-Object { 
    $_.status -eq "RESERVED" -and ($_.users -eq $null -or $_.users.Count -eq 0)
}

# Identify unused firewall rules (simplified check)
$suspiciousFirewallRules = $firewallRules | Where-Object {
    $_.name -match "(test|temp|demo|default)" -and $_.name -ne "default-allow-internal" -and $_.name -ne "default-allow-ssh"
}

# Identify empty backend services
$emptyBackendServices = $backendServices | Where-Object {
    ($_.backends -eq $null -or $_.backends.Count -eq 0)
}

# Identify empty target pools
$emptyTargetPools = $targetPools | Where-Object {
    ($_.instances -eq $null -or $_.instances.Count -eq 0)
}

# Identify forwarding rules with no backends
$suspiciousForwardingRules = $forwardingRules | Where-Object {
    # This is a simplified check - in practice you'd want to verify the target actually exists
    $_.target -eq $null -or $_.target -eq ""
}

# Identify old snapshots
$oldSnapshots = $snapshots | Where-Object {
    if ($_.creationTimestamp) {
        $snapshotDate = [DateTime]::Parse($_.creationTimestamp)
        $ageInDays = ($currentDate - $snapshotDate).TotalDays
        $ageInDays -gt $DaysThreshold
    } else {
        $false
    }
}

# Identify old custom images
$oldCustomImages = $customImages | Where-Object {
    if ($_.creationTimestamp) {
        $imageDate = [DateTime]::Parse($_.creationTimestamp)
        $ageInDays = ($currentDate - $imageDate).TotalDays
        $ageInDays -gt $DaysThreshold -and $_.name -match "(test|temp|backup|old)"
    } else {
        $false
    }
}

# Identify unused service accounts (basic check)
$unusedServiceAccounts = $serviceAccounts | Where-Object {
    $_.email -match "(test|temp|demo)" -and $_.email -notmatch "@gserviceaccount.com$"
}

Write-Host "Resource Analysis Summary:" -ForegroundColor Yellow
Write-Host "   Orphaned Persistent Disks: $($orphanedDisks.Count) out of $($allDisks.Count) total" -ForegroundColor White
Write-Host "   Unattached Static IPs: $($unattachedStaticIPs.Count) out of $($staticIPs.Count) total" -ForegroundColor White
Write-Host "   Suspicious Firewall Rules: $($suspiciousFirewallRules.Count) out of $($firewallRules.Count) total" -ForegroundColor White
Write-Host "   Empty Backend Services: $($emptyBackendServices.Count) out of $($backendServices.Count) total" -ForegroundColor White
Write-Host "   Empty Target Pools: $($emptyTargetPools.Count) out of $($targetPools.Count) total" -ForegroundColor White
Write-Host "   Suspicious Forwarding Rules: $($suspiciousForwardingRules.Count) out of $($forwardingRules.Count) total" -ForegroundColor White
Write-Host "   Old Snapshots (>$DaysThreshold days): $($oldSnapshots.Count) out of $($snapshots.Count) total" -ForegroundColor White
Write-Host "   Old Custom Images: $($oldCustomImages.Count) out of $($customImages.Count) total" -ForegroundColor White
Write-Host "   Cloud SQL Instances: $($sqlInstances.Count)" -ForegroundColor White
Write-Host "   Cloud Functions: $($cloudFunctions.Count)" -ForegroundColor White

# Enhanced suspicious patterns to detect
$suspiciousPatterns = @(
    @{
        Name="No Labels"
        Pattern={param($r) ($null -eq $r.labels) -or ($r.labels.Count -eq 0)}
        Risk="High"
        Description="Resources without proper labeling are hard to track and manage"
        CostImpact="Medium"
    },
    @{
        Name="Test/Temp Names"
        Pattern={param($r) $r.name -match "(test|temp|demo|poc|backup|old|delete|tmp)"}
        Risk="High"
        Description="Resources with temporary-sounding names are often forgotten after testing"
        CostImpact="High"
    },
    @{
        Name="Legacy Machine Types"
        Pattern={param($r) $r.machineType -match "(f1-micro|g1-small|n1-standard-1)" -and $r.status -eq "RUNNING"}
        Risk="Medium"
        Description="Legacy machine types are less cost-efficient than newer types"
        CostImpact="Medium"
    },
    @{
        Name="Test Storage Buckets"
        Pattern={param($r) $r.name -match "(test|temp|backup|dev|demo|poc)"}
        Risk="Medium"
        Description="Storage buckets with test-like names may contain unused data"
        CostImpact="Medium"
    },
    @{
        Name="Development SQL Instances"
        Pattern={param($r) $r.name -match "(test|temp|dev|demo)" -and $r.state -eq "RUNNABLE"}
        Risk="High"
        Description="Development SQL instances running in production can be expensive"
        CostImpact="High"
    }
)

# Initialize results
$suspiciousResources = @()

# Check Compute Engine instances against patterns
foreach ($instance in $computeInstances | Where-Object { $_.status -ne "TERMINATED" }) {
    foreach ($pattern in $suspiciousPatterns) {
        if (& $pattern.Pattern $instance) {
            $additionalInfo = "Machine Type: $($instance.machineType.Split('/')[-1]), Status: $($instance.status)"
            if ($instance.creationTimestamp) {
                $creationDate = [DateTime]::Parse($instance.creationTimestamp)
                $ageInDays = [Math]::Round(($currentDate - $creationDate).TotalDays)
                $additionalInfo += ", Age: $ageInDays days"
            }
            
            $zone = if ($instance.zone) { $instance.zone.Split('/')[-1] } else { "Unknown" }
            
            $suspiciousResources += [PSCustomObject]@{
                ResourceName = $instance.name
                ResourceType = "Compute Engine Instance"
                ResourceGroup = $zone
                Location = $zone
                SuspiciousPattern = $pattern.Name
                RiskLevel = $pattern.Risk
                Description = $pattern.Description
                CostImpact = $pattern.CostImpact
                Tags = if ($instance.labels) { ($instance.labels | ConvertTo-Json -Compress) } else { "None" }
                EstimatedMonthlyCost = "Varies by type"
                AdditionalInfo = $additionalInfo
            }
        }
    }
}

# Check Cloud Storage buckets against patterns
foreach ($bucket in $gcsBuckets) {
    foreach ($pattern in $suspiciousPatterns) {
        if (& $pattern.Pattern $bucket) {
            $ageInfo = ""
            if ($bucket.timeCreated) {
                $creationDate = [DateTime]::Parse($bucket.timeCreated)
                $ageInDays = [Math]::Round(($currentDate - $creationDate).TotalDays)
                $ageInfo = "Age: $ageInDays days"
            }
            
            $suspiciousResources += [PSCustomObject]@{
                ResourceName = $bucket.name
                ResourceType = "Cloud Storage Bucket"
                ResourceGroup = "Global"
                Location = "Global"
                SuspiciousPattern = $pattern.Name
                RiskLevel = $pattern.Risk
                Description = $pattern.Description
                CostImpact = $pattern.CostImpact
                Tags = if ($bucket.labels) { ($bucket.labels | ConvertTo-Json -Compress) } else { "None" }
                EstimatedMonthlyCost = "Varies by usage"
                AdditionalInfo = $ageInfo
            }
        }
    }
}

# Check Cloud SQL instances against patterns
foreach ($sqlInstance in $sqlInstances) {
    foreach ($pattern in $suspiciousPatterns) {
        if (& $pattern.Pattern $sqlInstance) {
            $additionalInfo = "Tier: $($sqlInstance.settings.tier), State: $($sqlInstance.state)"
            if ($sqlInstance.createTime) {
                $creationDate = [DateTime]::Parse($sqlInstance.createTime)
                $ageInDays = [Math]::Round(($currentDate - $creationDate).TotalDays)
                $additionalInfo += ", Age: $ageInDays days"
            }
            
            # Estimate cost based on tier
            $estimatedCost = switch -Regex ($sqlInstance.settings.tier) {
                "db-f1-micro" { "$7.67" }
                "db-g1-small" { "$25.55" }
                "db-n1-standard-1" { "$46.00" }
                "db-n1-standard-2" { "$92.00" }
                default { "Varies by tier" }
            }
            
            $suspiciousResources += [PSCustomObject]@{
                ResourceName = $sqlInstance.name
                ResourceType = "Cloud SQL Instance"
                ResourceGroup = $sqlInstance.region
                Location = $sqlInstance.region
                SuspiciousPattern = $pattern.Name
                RiskLevel = $pattern.Risk
                Description = $pattern.Description
                CostImpact = $pattern.CostImpact
                Tags = if ($sqlInstance.settings.userLabels) { ($sqlInstance.settings.userLabels | ConvertTo-Json -Compress) } else { "None" }
                EstimatedMonthlyCost = $estimatedCost
                AdditionalInfo = $additionalInfo
            }
        }
    }
}

# Add orphaned persistent disks
foreach ($disk in $orphanedDisks) {
    $createdDate = if ($disk.creationTimestamp) { [DateTime]::Parse($disk.creationTimestamp) } else { $null }
    $ageInDays = if ($createdDate) { [Math]::Round(($currentDate - $createdDate).TotalDays) } else { "Unknown" }
    
    # Estimate monthly cost based on disk type and size
    $sizeGB = [int]$disk.sizeGb
    $estimatedCost = switch ($disk.type.Split('/')[-1]) {
        "pd-standard" { [Math]::Round($sizeGB * 0.04, 2) }
        "pd-balanced" { [Math]::Round($sizeGB * 0.10, 2) }
        "pd-ssd" { [Math]::Round($sizeGB * 0.17, 2) }
        "pd-extreme" { [Math]::Round($sizeGB * 0.125, 2) }
        default { [Math]::Round($sizeGB * 0.04, 2) }
    }
    
    $zone = if ($disk.zone) { $disk.zone.Split('/')[-1] } else { "Unknown" }
    $diskType = if ($disk.type) { $disk.type.Split('/')[-1] } else { "Unknown" }
    
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $disk.name
        ResourceType = "Persistent Disk"
        ResourceGroup = $zone
        Location = $zone
        SuspiciousPattern = "Orphaned Disk"
        RiskLevel = "High"
        Description = "Unattached persistent disk that may be forgotten and incurring costs"
        CostImpact = "High"
        Tags = if ($disk.labels) { ($disk.labels | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "$" + $estimatedCost
        AdditionalInfo = "Size: ${sizeGB}GB, Type: $diskType, Age: $ageInDays days"
    }
}

# Add unattached static IPs
foreach ($staticIP in $unattachedStaticIPs) {
    $region = if ($staticIP.region) { $staticIP.region.Split('/')[-1] } else { "Global" }
    $ipType = if ($staticIP.addressType) { $staticIP.addressType } else { "EXTERNAL" }
    
    # Regional IPs cost $1.46/month, Global IPs cost $1.46/month when unused
    $estimatedCost = if ($ipType -eq "INTERNAL") { "Free" } else { "$1.46" }
    
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $staticIP.name
        ResourceType = "Static IP Address"
        ResourceGroup = $region
        Location = $region
        SuspiciousPattern = "Unattached Static IP"
        RiskLevel = "Medium"
        Description = "Static IP address not attached to any resource but still incurring charges"
        CostImpact = "Low"
        Tags = if ($staticIP.labels) { ($staticIP.labels | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = $estimatedCost
        AdditionalInfo = "IP: $($staticIP.address), Type: $ipType"
    }
}

# Add suspicious firewall rules
foreach ($fwRule in $suspiciousFirewallRules) {
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $fwRule.name
        ResourceType = "Firewall Rule"
        ResourceGroup = "Global"
        Location = "Global"
        SuspiciousPattern = "Suspicious Firewall Rule"
        RiskLevel = "Low"
        Description = "Firewall rule with test/demo naming that may be leftover from testing"
        CostImpact = "None"
        Tags = if ($fwRule.labels) { ($fwRule.labels | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "Free"
        AdditionalInfo = "Direction: $($fwRule.direction), Priority: $($fwRule.priority)"
    }
}

# Add empty backend services
foreach ($backendSvc in $emptyBackendServices) {
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $backendSvc.name
        ResourceType = "Backend Service"
        ResourceGroup = "Global"
        Location = "Global"
        SuspiciousPattern = "Empty Backend Service"
        RiskLevel = "Medium"
        Description = "Backend service with no backends configured"
        CostImpact = "Low"
        Tags = if ($backendSvc.labels) { ($backendSvc.labels | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "Free"
        AdditionalInfo = "Protocol: $($backendSvc.protocol), Load Balancing: $($backendSvc.loadBalancingScheme)"
    }
}

# Add empty target pools
foreach ($targetPool in $emptyTargetPools) {
    $region = if ($targetPool.region) { $targetPool.region.Split('/')[-1] } else { "Unknown" }
    
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $targetPool.name
        ResourceType = "Target Pool"
        ResourceGroup = $region
        Location = $region
        SuspiciousPattern = "Empty Target Pool"
        RiskLevel = "Medium"
        Description = "Target pool with no instances configured"
        CostImpact = "None"
        Tags = "None"
        EstimatedMonthlyCost = "Free"
        AdditionalInfo = "Session Affinity: $($targetPool.sessionAffinity)"
    }
}

# Add old snapshots
foreach ($snapshot in $oldSnapshots) {
    $snapshotDate = [DateTime]::Parse($snapshot.creationTimestamp)
    $ageInDays = [Math]::Round(($currentDate - $snapshotDate).TotalDays)
    $sizeGB = [int]$snapshot.storageBytes / 1GB
    $estimatedCost = [Math]::Round($sizeGB * 0.026, 2) # $0.026 per GB/month for snapshots
    
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $snapshot.name
        ResourceType = "Disk Snapshot"
        ResourceGroup = "Global"
        Location = "Global"
        SuspiciousPattern = "Old Snapshot"
        RiskLevel = "Medium"
        Description = "Snapshot older than $DaysThreshold days"
        CostImpact = "Medium"
        Tags = if ($snapshot.labels) { ($snapshot.labels | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "$" + $estimatedCost
        AdditionalInfo = "Size: $([Math]::Round($sizeGB, 1))GB, Age: $ageInDays days"
    }
}

# Add old custom images
foreach ($image in $oldCustomImages) {
    $imageDate = [DateTime]::Parse($image.creationTimestamp)
    $ageInDays = [Math]::Round(($currentDate - $imageDate).TotalDays)
    $sizeGB = [int]$image.archiveSizeBytes / 1GB
    $estimatedCost = [Math]::Round($sizeGB * 0.043, 2) # $0.043 per GB/month for images
    
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $image.name
        ResourceType = "Custom Image"
        ResourceGroup = "Global"
        Location = "Global"
        SuspiciousPattern = "Old Custom Image"
        RiskLevel = "Medium"
        Description = "Custom image older than $DaysThreshold days with test-like name"
        CostImpact = "Medium"
        Tags = if ($image.labels) { ($image.labels | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "$" + $estimatedCost
        AdditionalInfo = "Size: $([Math]::Round($sizeGB, 1))GB, Age: $ageInDays days, Family: $($image.family)"
    }
}

# Add unused service accounts
foreach ($sa in $unusedServiceAccounts) {
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $sa.displayName
        ResourceType = "Service Account"
        ResourceGroup = "Global"
        Location = "Global"
        SuspiciousPattern = "Test Service Account"
        RiskLevel = "Low"
        Description = "Service account with test/demo naming pattern"
        CostImpact = "None"
        Tags = "None"
        EstimatedMonthlyCost = "Free"
        AdditionalInfo = "Email: $($sa.email), Enabled: $($sa.disabled -eq $false)"
    }
}

# Calculate total estimated monthly savings
$totalEstimatedSavings = ($suspiciousResources | Where-Object { $_.EstimatedMonthlyCost -ne "Unknown" -and $_.EstimatedMonthlyCost -ne "" -and $_.EstimatedMonthlyCost -ne "Free" -and $_.EstimatedMonthlyCost -notmatch "Varies" } | ForEach-Object { 
    $cost = $_.EstimatedMonthlyCost -replace '\$', '' -replace '-.*', ''
    try { [double]$cost } catch { 0 }
} | Measure-Object -Sum).Sum

# Generate Enhanced HTML Report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>🕵️ Forgotten Resource Detective Report - GCP</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #4285f4 0%, #34a853 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .summary { background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .savings-highlight { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: white; padding: 15px; border-radius: 10px; text-align: center; margin: 20px 0; }
        .risk-high { border-left: 5px solid #ff4757; background-color: #fff5f5; }
        .risk-medium { border-left: 5px solid #ffa502; background-color: #fffaf0; }
        .risk-low { border-left: 5px solid #26de81; background-color: #f0fff4; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .footer { text-align: center; margin-top: 20px; color: #666; }
        .tip { background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .orphan-highlight { background: #ffebee; border: 2px solid #f44336; border-radius: 5px; }
        .cost-cell { font-weight: bold; color: #d32f2f; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🕵️ Forgotten Resource Detective - GCP</h1>
        <p>Project: $ProjectId | Account: $accountInfo | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="savings-highlight">
        <h2>💰 Potential Monthly Savings</h2>
        <h3>$([Math]::Round($totalEstimatedSavings, 2)) USD</h3>
        <p>From identified orphaned and suspicious resources</p>
    </div>
    
    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <p><strong>Total Suspicious Resources Found:</strong> $($suspiciousResources.Count)</p>
        <p><strong>🔥 Critical Issues:</strong></p>
        <ul>
            <li>💾 Orphaned Persistent Disks: $($orphanedDisks.Count) (Direct cost impact)</li>
            <li>🌐 Unattached Static IPs: $($unattachedStaticIPs.Count) (Monthly charges)</li>
            <li>⚖️ Empty Backend Services: $($emptyBackendServices.Count) (Configuration overhead)</li>
            <li>🎯 Empty Target Pools: $($emptyTargetPools.Count) (Management overhead)</li>
            <li>🛡️ Suspicious Firewall Rules: $($suspiciousFirewallRules.Count) (Security risk)</li>
            <li>📸 Old Snapshots: $($oldSnapshots.Count) (Storage costs)</li>
            <li>🖼️ Old Custom Images: $($oldCustomImages.Count) (Storage costs)</li>
            <li>🗄️ Cloud SQL Instances: $($sqlInstances.Count) (High cost potential)</li>
        </ul>
        <p><strong>📈 Risk Distribution:</strong></p>
        <p><strong>High Risk:</strong> $(($suspiciousResources | Where-Object {$_.RiskLevel -eq 'High'}).Count) | 
           <strong>Medium Risk:</strong> $(($suspiciousResources | Where-Object {$_.RiskLevel -eq 'Medium'}).Count) | 
           <strong>Low Risk:</strong> $(($suspiciousResources | Where-Object {$_.RiskLevel -eq 'Low'}).Count)</p>
    </div>
    
    <div class="tip">
        <h3>💡 FinOps Action Priority</h3>
        <ul>
            <li><strong>🔥 Immediate (Week 1):</strong> Delete orphaned persistent disks and release unattached static IPs</li>
            <li><strong>⚖️ Quick Wins (Week 2):</strong> Review empty backend services and target pools</li>
            <li><strong>📊 Modernization (Month 1):</strong> Upgrade legacy machine types to newer generations</li>
            <li><strong>🏷️ Governance (Ongoing):</strong> Implement labeling policies for new resources</li>
            <li><strong>🔄 Automation (Month 2):</strong> Set up Cloud Monitoring and budgets for cost tracking</li>
        </ul>
        
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 10px; margin-top: 15px;">
            <h4>🎯 Top 3 Cost Optimization Opportunities:</h4>
            <ol>
                <li><strong>Orphaned Persistent Disks:</strong> $([Math]::Round($totalEstimatedSavings, 2)) USD/month potential savings</li>
                <li><strong>Cloud SQL Review:</strong> $($sqlInstances.Count) instances to validate (can be $25-100+/month each)</li>
                <li><strong>Legacy Compute Instances:</strong> $(($suspiciousResources | Where-Object {$_.SuspiciousPattern -eq "Legacy Machine Types"}).Count) instances using outdated types</li>
            </ol>
        </div>
    </div>
    
    <h2>🔍 Detailed Findings</h2>
    <table>
        <tr>
            <th>Risk</th>
            <th>Resource Name</th>
            <th>Type</th>
            <th>Zone/Region</th>
            <th>Issue Found</th>
            <th>Cost Impact</th>
            <th>Additional Info</th>
            <th>Labels</th>
        </tr>
"@

# Add table rows - prioritize orphaned disks
$sortedResources = $suspiciousResources | Sort-Object @{Expression={if($_.SuspiciousPattern -eq "Orphaned Disk") {0} else {1}}}, RiskLevel, ResourceName

foreach ($resource in $sortedResources) {
    $riskClass = "risk-" + $resource.RiskLevel.ToLower()
    $rowClass = if ($resource.SuspiciousPattern -eq "Orphaned Disk") { "$riskClass orphan-highlight" } else { $riskClass }
    $costDisplay = if ($resource.EstimatedMonthlyCost -and $resource.EstimatedMonthlyCost -ne "Unknown" -and $resource.EstimatedMonthlyCost -notmatch "Varies") { 
        "<span class='cost-cell'>$($resource.EstimatedMonthlyCost)</span>" 
    } else { 
        $resource.CostImpact
    }
    
    $htmlReport += @"
        <tr class="$rowClass">
            <td><strong>$($resource.RiskLevel)</strong></td>
            <td>$($resource.ResourceName)</td>
            <td>$($resource.ResourceType)</td>
            <td>$($resource.Location)</td>
            <td>$($resource.SuspiciousPattern)</td>
            <td>$costDisplay</td>
            <td>$($resource.AdditionalInfo)</td>
            <td>$($resource.Tags)</td>
        </tr>
"@
}

$htmlReport += @"
    </table>
    
    <div class="tip">
        <h3>🎯 Quick Actions & gcloud CLI Commands</h3>
        
        <h4>🗑️ Cleanup Commands (Use with caution!):</h4>
        <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px;">
# List all orphaned resources for review
gcloud compute disks list --filter="users:() AND status:READY" --format="table(name,zone,sizeGb,type)"
gcloud compute addresses list --filter="users:() AND status:RESERVED" --format="table(name,region,address,addressType)"
gcloud compute snapshots list --filter="creationTimestamp<-P${DaysThreshold}D" --format="table(name,creationTimestamp,diskSizeGb)"

# Delete commands (VERIFY FIRST!)
# gcloud compute disks delete DISK_NAME --zone=ZONE_NAME --quiet
# gcloud compute addresses delete ADDRESS_NAME --region=REGION_NAME --quiet
# gcloud compute snapshots delete SNAPSHOT_NAME --quiet
# gcloud compute images delete IMAGE_NAME --quiet
# gcloud compute firewall-rules delete RULE_NAME --quiet
        </pre>
        
        <h4>📊 Cost Analysis Commands:</h4>
        <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px;">
# Get billing information (requires billing admin access)
gcloud billing accounts list
gcloud billing projects describe PROJECT_ID

# Check resource usage and costs
gcloud compute instances list --format="table(name,zone,machineType,status,creationTimestamp)"
gcloud sql instances list --format="table(name,region,tier,state,createTime)"

# List unlabeled resources
gcloud compute instances list --filter="NOT labels.*" --format="table(name,zone,machineType)"
gcloud compute disks list --filter="NOT labels.*" --format="table(name,zone,sizeGb,type)"
        </pre>
        
        <h4>🔧 Automation & Governance Scripts:</h4>
        <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px;">
# Set up budget alerts
gcloud billing budgets create --billing-account=BILLING_ACCOUNT_ID --display-name="Monthly Budget" --budget-amount=100USD

# Create organization policy for mandatory labels
gcloud resource-manager org-policies set-policy policy.yaml

# Set up monitoring alerts for unattached disks
gcloud alpha monitoring policies create --policy-from-file=disk-policy.yaml

# Enable resource location restriction
gcloud resource-manager org-policies set-policy location-policy.yaml
        </pre>
        
        <div style="background: #ffebee; border: 1px solid #f44336; border-radius: 5px; padding: 10px; margin-top: 10px;">
            <p><strong>WARNING:</strong> Always verify resources are truly unused before deletion. Check with application owners and review dependencies! Some managed services create resources automatically.</p>
        </div>
    </div>
    
    <div class="tip">
        <h3>🛡️ GCP Security & Governance Best Practices</h3>
        <ul>
            <li><strong>🏷️ Implement mandatory labeling:</strong> Use Organization Policies to enforce Environment, Owner, and Project labels</li>
            <li><strong>💰 Set up Billing Budgets:</strong> Create alerts when spending exceeds thresholds</li>
            <li><strong>📊 Use Cloud Billing Reports:</strong> Analyze spending patterns and identify cost anomalies</li>
            <li><strong>🔍 Enable Cloud Asset Inventory:</strong> Track resource creation and modification for audit trails</li>
            <li><strong>⚡ Implement lifecycle policies:</strong> Automate snapshot cleanup and Cloud Storage object transitions</li>
            <li><strong>🎯 Use Recommender API:</strong> Get recommendations for cost optimization and security</li>
            <li><strong>🔄 Set up Cloud Monitoring:</strong> Monitor resource utilization and set up automated scaling</li>
            <li><strong>🏗️ Use Resource Hierarchy:</strong> Organize projects properly for better governance</li>
        </ul>
    </div>
    
    <div class="tip">
        <h3>🚀 Advanced GCP FinOps Strategies</h3>
        <ul>
            <li><strong>💡 Committed Use Discounts:</strong> Analyze workload patterns for 1-3 year commitments</li>
            <li><strong>🎯 Sustained Use Discounts:</strong> Automatically applied for consistent usage</li>
            <li><strong>⚡ Preemptible/Spot Instances:</strong> Use for fault-tolerant workloads (60-90% savings)</li>
            <li><strong>🔄 Rightsizing Recommendations:</strong> Use Cloud Monitoring to identify oversized instances</li>
            <li><strong>📦 Custom Machine Types:</strong> Create machines with exact specifications needed</li>
            <li><strong>🌍 Regional Optimization:</strong> Choose cost-effective regions for workloads</li>
            <li><strong>📊 BigQuery Slot Reservations:</strong> For predictable analytics workloads</li>
            <li><strong>🔐 IAM Best Practices:</strong> Implement least privilege to prevent resource sprawl</li>
        </ul>
    </div>
    
    <div class="footer">
        <p>🤖 Generated by Enhanced Forgotten Resource Detective for GCP | Part of "FinOps for Everyone" series</p>
        <p>💡 <strong>Next Steps:</strong> Focus on orphaned persistent disks first for immediate savings, then review Cloud SQL instances</p>
        <p>🔄 <strong>Automation Tip:</strong> Consider using Cloud Functions to automatically detect and alert on orphaned resources</p>
        <p>📚 <strong>Learn More:</strong> Check out GCP Cost Optimization documentation and Recommender API for advanced insights</p>
    </div>
</body>
</html>
"@

# Save report
$htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8

# Export to CSV
Write-Host "`nExporting results to CSV..." -ForegroundColor Green
$csvData = $suspiciousResources |
    Select-Object `
        @{Name='ResourceName';        Expression={$_.ResourceName}}, `
        @{Name='ResourceType';        Expression={$_.ResourceType}}, `
        @{Name='ResourceGroup';       Expression={$_.ResourceGroup}}, `
        @{Name='Location';            Expression={$_.Location}}, `
        @{Name='SuspiciousPattern';   Expression={$_.SuspiciousPattern}}, `
        @{Name='RiskLevel';           Expression={$_.RiskLevel}}, `
        @{Name='Description';         Expression={$_.Description}}, `
        @{Name='CostImpact';          Expression={$_.CostImpact}}, `
        @{Name='EstimatedMonthlyCost';Expression={
            if ($_.EstimatedMonthlyCost -and $_.EstimatedMonthlyCost -ne 'Unknown' -and $_.EstimatedMonthlyCost -ne 'Free' -and $_.EstimatedMonthlyCost -notmatch 'Varies') {
                $_.EstimatedMonthlyCost -replace '[^\d.]',''
            }
            else {
                $_.EstimatedMonthlyCost
            }
        }}, `
        @{Name='AdditionalInfo';      Expression={$_.AdditionalInfo}}, `
        @{Name='Tags';                Expression={$_.Tags}} |
    Export-Csv -Path $CsvOutputPath -NoTypeInformation -Encoding UTF8

# Final console summary
Write-Host "`nEnhanced GCP report generated successfully!" -ForegroundColor Green
Write-Host "HTML Report: $OutputPath"              -ForegroundColor Cyan
Write-Host "CSV Export: $CsvOutputPath"          -ForegroundColor Cyan

# Risk distribution counts
$highCount = ($suspiciousResources | Where-Object { $_.RiskLevel -eq 'High'   }).Count
$medCount  = ($suspiciousResources | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
$lowCount  = ($suspiciousResources | Where-Object { $_.RiskLevel -eq 'Low'    }).Count

Write-Host "`nQuick Summary:"                   -ForegroundColor Magenta
Write-Host "Potential monthly savings: $([Math]::Round($totalEstimatedSavings,2)) USD" -ForegroundColor Green
Write-Host "Critical Issues:"                  -ForegroundColor Red
Write-Host "   Orphaned Persistent Disks: $($orphanedDisks.Count)" -ForegroundColor White
Write-Host "   Unattached Static IPs: $($unattachedStaticIPs.Count)" -ForegroundColor White
Write-Host "   Empty Backend Services: $($emptyBackendServices.Count)" -ForegroundColor White
Write-Host "   Empty Target Pools: $($emptyTargetPools.Count)" -ForegroundColor White
Write-Host "   Suspicious Firewall Rules: $($suspiciousFirewallRules.Count)" -ForegroundColor White
Write-Host "   Old Snapshots (>$DaysThreshold days): $($oldSnapshots.Count)" -ForegroundColor White
Write-Host "   Old Custom Images: $($oldCustomImages.Count)" -ForegroundColor White
Write-Host "   Cloud SQL Instances: $($sqlInstances.Count)" -ForegroundColor White

Write-Host "`nRisk Distribution:"               -ForegroundColor Yellow
Write-Host "   High Risk:   $highCount resources"   -ForegroundColor Red
Write-Host "   Medium Risk: $medCount resources"    -ForegroundColor Yellow
Write-Host "   Low Risk:    $lowCount resources"    -ForegroundColor Green

Write-Host "`nRecommended Actions:"           -ForegroundColor Cyan
Write-Host "1. Delete orphaned persistent disks and release unattached static IPs" -ForegroundColor White
Write-Host "2. Review Cloud SQL instances for test/dev environments in production" -ForegroundColor White
Write-Host "3. Clean up empty backend services and target pools" -ForegroundColor White
Write-Host "4. Implement mandatory labeling with Organization Policies" -ForegroundColor White
Write-Host "5. Set up Billing Budgets and Cloud Monitoring for ongoing cost tracking" -ForegroundColor White
Write-Host "6. Review and delete old snapshots and custom images older than $DaysThreshold days" -ForegroundColor White

Write-Host "`n💡 GCP-Specific Pro Tips:"                    -ForegroundColor Yellow
Write-Host "- Use 'gcloud recommender' commands for ML-powered optimization suggestions" -ForegroundColor Gray
Write-Host "- Enable 'Cloud Asset Inventory' for comprehensive resource tracking" -ForegroundColor Gray
Write-Host "- Consider 'Committed Use Discounts' for long-running workloads" -ForegroundColor Gray
Write-Host "- Use 'Preemptible VMs' for fault-tolerant batch workloads (60-90% savings)" -ForegroundColor Gray
Write-Host "- Implement 'Cloud Scheduler' to automatically start/stop development resources" -ForegroundColor Gray
Write-Host "- Use 'Organization Policies' to enforce governance at scale" -ForegroundColor Gray
