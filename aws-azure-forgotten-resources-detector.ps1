# 🕵️ Forgotten Resource Detective for AWS (Enhanced)
# A simple script to find resources that might be forgotten and costing you money
# Part of the "FinOps for Everyone" series

param(
    [Parameter(Mandatory=$true)]
    [string]$Region,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysThreshold = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "forgotten-resources-report.html",
    
    [Parameter(Mandatory=$false)]
    [string]$CsvOutputPath = "forgotten-resources-report.csv",
    
    [Parameter(Mandatory=$false)]
    [string]$ProfileName = "default"
)

# 🚀 Initialize AWS PowerShell (make sure AWS CLI is configured)
Write-Host "Starting AWS Forgotten Resource Detective..." -ForegroundColor Cyan
Write-Host "Looking for resources older than $DaysThreshold days with suspicious patterns..." -ForegroundColor Yellow

# Set AWS region and profile
$env:AWS_DEFAULT_REGION = $Region
if ($ProfileName -ne "default") {
    $env:AWS_PROFILE = $ProfileName
}

# Test AWS CLI connectivity
try {
    $accountInfo = aws sts get-caller-identity | ConvertFrom-Json
    Write-Host "Connected to AWS Account: $($accountInfo.Account) as $($accountInfo.Arn)" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to AWS. Please ensure AWS CLI is configured with 'aws configure'"
    exit 1
}

# 💾 Get detailed EBS volume information to identify orphans
Write-Host "Analyzing EBS volumes..." -ForegroundColor Blue
$allVolumes = aws ec2 describe-volumes --query "Volumes[].{VolumeId:VolumeId, State:State, Size:Size, VolumeType:VolumeType, CreateTime:CreateTime, Attachments:Attachments, Tags:Tags, Encrypted:Encrypted, Iops:Iops}" | ConvertFrom-Json

# 🌐 Get detailed network information
Write-Host "Analyzing network resources..." -ForegroundColor Blue
$elasticIPs = aws ec2 describe-addresses --query "Addresses[].{PublicIp:PublicIp, AllocationId:AllocationId, AssociationId:AssociationId, InstanceId:InstanceId, NetworkInterfaceId:NetworkInterfaceId, Tags:Tags}" | ConvertFrom-Json
$networkInterfaces = aws ec2 describe-network-interfaces --query "NetworkInterfaces[].{NetworkInterfaceId:NetworkInterfaceId, Status:Status, Attachment:Attachment, Description:Description, Groups:Groups, Tags:Tags, InterfaceType:InterfaceType}" | ConvertFrom-Json
$securityGroups = aws ec2 describe-security-groups --query "SecurityGroups[].{GroupId:GroupId, GroupName:GroupName, Description:Description, IpPermissions:IpPermissions, IpPermissionsEgress:IpPermissionsEgress, Tags:Tags}" | ConvertFrom-Json

# ⚖️ Get load balancer information
Write-Host "Analyzing load balancers..." -ForegroundColor Blue
try {
    $classicLoadBalancers = aws elb describe-load-balancers --query "LoadBalancerDescriptions[].{LoadBalancerName:LoadBalancerName, DNSName:DNSName, Instances:Instances, CreatedTime:CreatedTime}" | ConvertFrom-Json
} catch {
    $classicLoadBalancers = @()
    Write-Host "No Classic Load Balancers found or permission denied" -ForegroundColor Gray
}

try {
    $applicationLoadBalancers = aws elbv2 describe-load-balancers --query "LoadBalancers[].{LoadBalancerArn:LoadBalancerArn, LoadBalancerName:LoadBalancerName, Type:Type, State:State, CreatedTime:CreatedTime}" | ConvertFrom-Json
} catch {
    $applicationLoadBalancers = @()
    Write-Host "No Application/Network Load Balancers found or permission denied" -ForegroundColor Gray
}

# 🖥️ Get EC2 instance information
Write-Host "Analyzing EC2 instances..." -ForegroundColor Blue
$ec2Instances = aws ec2 describe-instances --query "Reservations[].Instances[].{InstanceId:InstanceId, InstanceType:InstanceType, State:State.Name, LaunchTime:LaunchTime, Tags:Tags, Platform:Platform}" | ConvertFrom-Json

# 🗄️ Get S3 bucket information
Write-Host "Analyzing S3 buckets..." -ForegroundColor Blue
try {
    $s3Buckets = aws s3api list-buckets --query "Buckets[].{Name:Name, CreationDate:CreationDate}" | ConvertFrom-Json
    # Get bucket tagging for each bucket (this might take a while for many buckets)
    $s3BucketsWithTags = @()
    foreach ($bucket in $s3Buckets) {
        try {
            $tags = aws s3api get-bucket-tagging --bucket $bucket.Name --query "TagSet" 2>$null | ConvertFrom-Json
            $s3BucketsWithTags += [PSCustomObject]@{
                Name = $bucket.Name
                CreationDate = $bucket.CreationDate
                Tags = $tags
            }
        } catch {
            $s3BucketsWithTags += [PSCustomObject]@{
                Name = $bucket.Name
                CreationDate = $bucket.CreationDate
                Tags = $null
            }
        }
    }
} catch {
    $s3BucketsWithTags = @()
    Write-Host "Unable to list S3 buckets or permission denied" -ForegroundColor Gray
}

# 🔑 Get unused key pairs
Write-Host "Analyzing EC2 key pairs..." -ForegroundColor Blue
$keyPairs = aws ec2 describe-key-pairs --query "KeyPairs[].{KeyName:KeyName, KeyFingerprint:KeyFingerprint, Tags:Tags}" | ConvertFrom-Json

# 📸 Get snapshots
Write-Host "Analyzing EBS snapshots..." -ForegroundColor Blue
$snapshots = aws ec2 describe-snapshots --owner-ids self --query "Snapshots[].{SnapshotId:SnapshotId, VolumeId:VolumeId, State:State, StartTime:StartTime, VolumeSize:VolumeSize, Description:Description, Tags:Tags}" | ConvertFrom-Json

# 🎯 Get NAT Gateways
Write-Host "Analyzing NAT Gateways..." -ForegroundColor Blue
$natGateways = aws ec2 describe-nat-gateways --query "NatGateways[].{NatGatewayId:NatGatewayId, State:State, CreateTime:CreateTime, Tags:Tags}" | ConvertFrom-Json

# Calculate current date for age calculations
$currentDate = Get-Date

# Identify orphaned EBS volumes
$orphanedVolumes = $allVolumes | Where-Object { 
    $_.State -eq "available" -and ($_.Attachments -eq $null -or $_.Attachments.Count -eq 0)
}

# Identify unattached Elastic IPs
$unattachedEIPs = $elasticIPs | Where-Object { 
    [string]::IsNullOrEmpty($_.AssociationId) -and [string]::IsNullOrEmpty($_.InstanceId) -and [string]::IsNullOrEmpty($_.NetworkInterfaceId)
}

# Identify orphaned network interfaces (excluding managed service ENIs)
$orphanedENIs = $networkInterfaces | Where-Object { 
    $_.Status -eq "available" -and
    $_.Description -notmatch "^(ELB|RDSNetworkInterface|AWS Lambda VPC|ElastiCache|arn:aws)" -and
    $_.InterfaceType -ne "nat_gateway" -and
    $_.InterfaceType -ne "vpc_endpoint" -and
    ($_.Attachment -eq $null -or $_.Attachment.Status -eq "detached")
}

# Identify unused security groups (excluding default)
$unusedSecurityGroups = @()
foreach ($sg in ($securityGroups | Where-Object { $_.GroupName -ne "default" })) {
    $isUsed = $false
    
    # Check if used by EC2 instances
    foreach ($instance in $ec2Instances) {
        if ($instance.State -ne "terminated") {
            # Check if this SG is referenced (simplified check)
            if ($sg.GroupId) {
                $isUsed = $true
                break
            }
        }
    }
    
    # Check if used by ENIs
    foreach ($eni in $networkInterfaces) {
        if ($eni.Groups -and ($eni.Groups | Where-Object { $_.GroupId -eq $sg.GroupId })) {
            $isUsed = $true
            break
        }
    }
    
    if (-not $isUsed) {
        $unusedSecurityGroups += $sg
    }
}

# Identify potentially unused load balancers
$suspiciousClassicLBs = $classicLoadBalancers | Where-Object { 
    ($_.Instances -eq $null -or $_.Instances.Count -eq 0)
}

# Get target groups for ALB/NLB analysis
$suspiciousApplicationLBs = @()
foreach ($alb in $applicationLoadBalancers) {
    if ($alb.State.Code -eq "active") {
        try {
            $targetGroups = aws elbv2 describe-target-groups --load-balancer-arn $alb.LoadBalancerArn | ConvertFrom-Json
            $hasHealthyTargets = $false
            
            foreach ($tg in $targetGroups.TargetGroups) {
                $targets = aws elbv2 describe-target-health --target-group-arn $tg.TargetGroupArn | ConvertFrom-Json
                if ($targets.TargetHealthDescriptions -and ($targets.TargetHealthDescriptions | Where-Object { $_.TargetHealth.State -eq "healthy" })) {
                    $hasHealthyTargets = $true
                    break
                }
            }
            
            if (-not $hasHealthyTargets) {
                $suspiciousApplicationLBs += $alb
            }
        } catch {
            # If we can't check targets, mark as suspicious
            $suspiciousApplicationLBs += $alb
        }
    }
}

# Identify unused key pairs
$unusedKeyPairs = @()
foreach ($kp in $keyPairs) {
    $isUsed = $false
    foreach ($instance in $ec2Instances) {
        if ($instance.State -ne "terminated" -and $instance.KeyName -eq $kp.KeyName) {
            $isUsed = $true
            break
        }
    }
    if (-not $isUsed) {
        $unusedKeyPairs += $kp
    }
}

# Identify old snapshots (older than threshold)
$oldSnapshots = $snapshots | Where-Object {
    $snapshotDate = [DateTime]::Parse($_.StartTime)
    $ageInDays = ($currentDate - $snapshotDate).TotalDays
    $ageInDays -gt $DaysThreshold -and $_.State -eq "completed"
}

Write-Host "Resource Analysis Summary:" -ForegroundColor Yellow
Write-Host "   Orphaned EBS Volumes: $($orphanedVolumes.Count) out of $($allVolumes.Count) total" -ForegroundColor White
Write-Host "   Unattached Elastic IPs: $($unattachedEIPs.Count) out of $($elasticIPs.Count) total" -ForegroundColor White
Write-Host "   Orphaned ENIs: $($orphanedENIs.Count) out of $($networkInterfaces.Count) total" -ForegroundColor White
Write-Host "   Unused Security Groups: $($unusedSecurityGroups.Count) out of $($securityGroups.Count) total" -ForegroundColor White
Write-Host "   Suspicious Classic LBs: $($suspiciousClassicLBs.Count) out of $($classicLoadBalancers.Count) total" -ForegroundColor White
Write-Host "   Suspicious ALB/NLBs: $($suspiciousApplicationLBs.Count) out of $($applicationLoadBalancers.Count) total" -ForegroundColor White
Write-Host "   Unused Key Pairs: $($unusedKeyPairs.Count) out of $($keyPairs.Count) total" -ForegroundColor White
Write-Host "   Old Snapshots (>$DaysThreshold days): $($oldSnapshots.Count) out of $($snapshots.Count) total" -ForegroundColor White

# Enhanced suspicious patterns to detect
$suspiciousPatterns = @(
    @{
        Name="No Tags"
        Pattern={param($r) ($null -eq $r.Tags) -or ($r.Tags.Count -eq 0)}
        Risk="High"
        Description="Resources without proper tagging are hard to track and manage"
        CostImpact="Medium"
    },
    @{
        Name="Test/Temp Names"
        Pattern={param($r) $r.Name -match "(test|temp|demo|poc|backup|old|delete|tmp)" -or $r.InstanceId -match "(test|temp|demo|poc|backup|old|delete|tmp)"}
        Risk="High"
        Description="Resources with temporary-sounding names are often forgotten after testing"
        CostImpact="High"
    },
    @{
        Name="Old Generation Instances"
        Pattern={param($r) $r.InstanceType -match "(t1\.|m1\.|c1\.|cc1\.|m2\.|cr1\.|hi1\.|hs1\.|t2\.nano|t2\.micro)" -and $r.State -eq "running"}
        Risk="Medium"
        Description="Old generation instances are less cost-efficient than newer types"
        CostImpact="Medium"
    },
    @{
        Name="Test S3 Buckets"
        Pattern={param($r) $r.Name -match "(test|temp|backup|dev|demo|poc)"}
        Risk="Medium"
        Description="S3 buckets with test-like names may contain unused data"
        CostImpact="Medium"
    }
)

# Initialize results
$suspiciousResources = @()

# Check EC2 instances against patterns
foreach ($instance in $ec2Instances | Where-Object { $_.State -ne "terminated" }) {
    foreach ($pattern in $suspiciousPatterns) {
        if (& $pattern.Pattern $instance) {
            $additionalInfo = "Instance Type: $($instance.InstanceType), State: $($instance.State)"
            if ($instance.LaunchTime) {
                $launchDate = [DateTime]::Parse($instance.LaunchTime)
                $ageInDays = [Math]::Round(($currentDate - $launchDate).TotalDays)
                $additionalInfo += ", Age: $ageInDays days"
            }
            
            $suspiciousResources += [PSCustomObject]@{
                ResourceName = $instance.InstanceId
                ResourceType = "EC2 Instance"
                ResourceGroup = $Region
                Location = $Region
                SuspiciousPattern = $pattern.Name
                RiskLevel = $pattern.Risk
                Description = $pattern.Description
                CostImpact = $pattern.CostImpact
                Tags = if ($instance.Tags) { ($instance.Tags | ConvertTo-Json -Compress) } else { "None" }
                EstimatedMonthlyCost = "Varies by type"
                AdditionalInfo = $additionalInfo
            }
        }
    }
}

# Check S3 buckets against patterns
foreach ($bucket in $s3BucketsWithTags) {
    foreach ($pattern in $suspiciousPatterns) {
        if (& $pattern.Pattern $bucket) {
            $creationDate = [DateTime]::Parse($bucket.CreationDate)
            $ageInDays = [Math]::Round(($currentDate - $creationDate).TotalDays)
            
            $suspiciousResources += [PSCustomObject]@{
                ResourceName = $bucket.Name
                ResourceType = "S3 Bucket"
                ResourceGroup = "Global"
                Location = "Global"
                SuspiciousPattern = $pattern.Name
                RiskLevel = $pattern.Risk
                Description = $pattern.Description
                CostImpact = $pattern.CostImpact
                Tags = if ($bucket.Tags) { ($bucket.Tags | ConvertTo-Json -Compress) } else { "None" }
                EstimatedMonthlyCost = "Varies by usage"
                AdditionalInfo = "Age: $ageInDays days"
            }
        }
    }
}

# Add orphaned EBS volumes
foreach ($volume in $orphanedVolumes) {
    $createdDate = if ($volume.CreateTime) { [DateTime]::Parse($volume.CreateTime) } else { $null }
    $ageInDays = if ($createdDate) { [Math]::Round(($currentDate - $createdDate).TotalDays) } else { "Unknown" }
    
    # Estimate monthly cost based on volume type and size
    $estimatedCost = switch ($volume.VolumeType) {
        "gp2" { [Math]::Round($volume.Size * 0.10, 2) }
        "gp3" { [Math]::Round($volume.Size * 0.08, 2) }
        "io1" { [Math]::Round($volume.Size * 0.125 + ($volume.Iops * 0.065), 2) }
        "io2" { [Math]::Round($volume.Size * 0.125 + ($volume.Iops * 0.065), 2) }
        "st1" { [Math]::Round($volume.Size * 0.045, 2) }
        "sc1" { [Math]::Round($volume.Size * 0.025, 2) }
        default { [Math]::Round($volume.Size * 0.10, 2) }
    }
    
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $volume.VolumeId
        ResourceType = "EBS Volume"
        ResourceGroup = $Region
        Location = $Region
        SuspiciousPattern = "Orphaned Volume"
        RiskLevel = "High"
        Description = "Unattached EBS volume that may be forgotten and incurring costs"
        CostImpact = "High"
        Tags = if ($volume.Tags) { ($volume.Tags | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "$" + $estimatedCost
        AdditionalInfo = "Size: $($volume.Size)GB, Type: $($volume.VolumeType), Age: $ageInDays days, Encrypted: $($volume.Encrypted)"
    }
}

# Add unattached Elastic IPs
foreach ($eip in $unattachedEIPs) {
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $eip.PublicIp
        ResourceType = "Elastic IP"
        ResourceGroup = $Region
        Location = $Region
        SuspiciousPattern = "Unattached Elastic IP"
        RiskLevel = "Medium"
        Description = "Elastic IP not attached to any resource but still incurring charges"
        CostImpact = "Low"
        Tags = if ($eip.Tags) { ($eip.Tags | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "$3.65"
        AdditionalInfo = "Allocation ID: $($eip.AllocationId)"
    }
}

# Add orphaned ENIs
foreach ($eni in $orphanedENIs) {
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $eni.NetworkInterfaceId
        ResourceType = "Network Interface"
        ResourceGroup = $Region
        Location = $Region
        SuspiciousPattern = "Orphaned ENI"
        RiskLevel = "High"
        Description = "Network interface not attached to any instance"
        CostImpact = "Low"
        Tags = if ($eni.Tags) { ($eni.Tags | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "Free"
        AdditionalInfo = "Description: $($eni.Description), Status: $($eni.Status)"
    }
}

# Add unused security groups
foreach ($sg in $unusedSecurityGroups) {
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $sg.GroupName
        ResourceType = "Security Group"
        ResourceGroup = $Region
        Location = $Region
        SuspiciousPattern = "Unused Security Group"
        RiskLevel = "Low"
        Description = "Security group not protecting any resources"
        CostImpact = "None"
        Tags = if ($sg.Tags) { ($sg.Tags | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "Free"
        AdditionalInfo = "Group ID: $($sg.GroupId), Description: $($sg.Description)"
    }
}

# Add suspicious load balancers
foreach ($clb in $suspiciousClassicLBs) {
    $createdDate = if ($clb.CreatedTime) { [DateTime]::Parse($clb.CreatedTime) } else { $null }
    $ageInDays = if ($createdDate) { [Math]::Round(($currentDate - $createdDate).TotalDays) } else { "Unknown" }
    
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $clb.LoadBalancerName
        ResourceType = "Classic Load Balancer"
        ResourceGroup = $Region
        Location = $Region
        SuspiciousPattern = "Empty Load Balancer"
        RiskLevel = "High"
        Description = "Classic Load Balancer with no instances"
        CostImpact = "High"
        Tags = "None"
        EstimatedMonthlyCost = "$18.25"
        AdditionalInfo = "No attached instances, Age: $ageInDays days"
    }
}

foreach ($alb in $suspiciousApplicationLBs) {
    $createdDate = if ($alb.CreatedTime) { [DateTime]::Parse($alb.CreatedTime) } else { $null }
    $ageInDays = if ($createdDate) { [Math]::Round(($currentDate - $createdDate).TotalDays) } else { "Unknown" }
    
    $costEstimate = if ($alb.Type -eq "network") { "$16.20" } else { "$16.20" }
    
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $alb.LoadBalancerName
        ResourceType = "$($alb.Type) Load Balancer"
        ResourceGroup = $Region
        Location = $Region
        SuspiciousPattern = "Empty Load Balancer"
        RiskLevel = "High"
        Description = "Load balancer with no healthy targets"
        CostImpact = "High"
        Tags = "None"
        EstimatedMonthlyCost = $costEstimate
        AdditionalInfo = "No healthy targets, Age: $ageInDays days"
    }
}

# Add unused key pairs
foreach ($kp in $unusedKeyPairs) {
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $kp.KeyName
        ResourceType = "Key Pair"
        ResourceGroup = $Region
        Location = $Region
        SuspiciousPattern = "Unused Key Pair"
        RiskLevel = "Low"
        Description = "Key pair not used by any running instances"
        CostImpact = "None"
        Tags = if ($kp.Tags) { ($kp.Tags | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "Free"
        AdditionalInfo = "Fingerprint: $($kp.KeyFingerprint)"
    }
}

# Add old snapshots
foreach ($snapshot in $oldSnapshots) {
    $snapshotDate = [DateTime]::Parse($snapshot.StartTime)
    $ageInDays = [Math]::Round(($currentDate - $snapshotDate).TotalDays)
    $estimatedCost = [Math]::Round($snapshot.VolumeSize * 0.05, 2)
    
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $snapshot.SnapshotId
        ResourceType = "EBS Snapshot"
        ResourceGroup = $Region
        Location = $Region
        SuspiciousPattern = "Old Snapshot"
        RiskLevel = "Medium"
        Description = "Snapshot older than $DaysThreshold days"
        CostImpact = "Medium"
        Tags = if ($snapshot.Tags) { ($snapshot.Tags | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "$" + $estimatedCost
        AdditionalInfo = "Size: $($snapshot.VolumeSize)GB, Age: $ageInDays days, Description: $($snapshot.Description)"
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
    <title>🕵️ Forgotten Resource Detective Report - AWS</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #ff9500 0%, #ff6b35 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
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
        <h1>🕵️ Forgotten Resource Detective - AWS</h1>
        <p>Region: $Region | Account: $($accountInfo.Account) | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
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
            <li>💾 Orphaned EBS Volumes: $($orphanedVolumes.Count) (Direct cost impact)</li>
            <li>🔌 Orphaned ENIs: $($orphanedENIs.Count) (Management overhead)</li>
            <li>🌐 Unattached Elastic IPs: $($unattachedEIPs.Count) (Monthly charges)</li>
            <li>⚖️ Suspicious Load Balancers: $(($suspiciousClassicLBs.Count + $suspiciousApplicationLBs.Count)) (High cost impact)</li>
            <li>🛡️ Unused Security Groups: $($unusedSecurityGroups.Count) (Management overhead)</li>
            <li>🔑 Unused Key Pairs: $($unusedKeyPairs.Count) (Security risk)</li>
            <li>📸 Old Snapshots: $($oldSnapshots.Count) (Storage costs)</li>
        </ul>
        <p><strong>📈 Risk Distribution:</strong></p>
        <p><strong>High Risk:</strong> $(($suspiciousResources | Where-Object {$_.RiskLevel -eq 'High'}).Count) | 
           <strong>Medium Risk:</strong> $(($suspiciousResources | Where-Object {$_.RiskLevel -eq 'Medium'}).Count) | 
           <strong>Low Risk:</strong> $(($suspiciousResources | Where-Object {$_.RiskLevel -eq 'Low'}).Count)</p>
    </div>
    
    <div class="tip">
        <h3>💡 FinOps Action Priority</h3>
        <ul>
            <li><strong>🔥 Immediate (Week 1):</strong> Delete orphaned EBS volumes, release unattached Elastic IPs</li>
            <li><strong>⚖️ Quick Wins (Week 2):</strong> Review empty load balancers and unused security groups</li>
            <li><strong>📊 Modernization (Month 1):</strong> Upgrade old generation EC2 instances to newer types</li>
            <li><strong>🏷️ Governance (Ongoing):</strong> Implement tagging policies for new resources</li>
            <li><strong>🔄 Automation (Month 2):</strong> Set up AWS Config rules and budgets for cost monitoring</li>
        </ul>
        
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 10px; margin-top: 15px;">
            <h4>🎯 Top 3 Cost Optimization Opportunities:</h4>
            <ol>
                <li><strong>Orphaned EBS Volumes:</strong> $([Math]::Round($totalEstimatedSavings, 2)) USD/month potential savings</li>
                <li><strong>Load Balancer Review:</strong> $(($suspiciousClassicLBs.Count + $suspiciousApplicationLBs.Count)) LBs to validate (~$16-18/month each)</li>
                <li><strong>Old Generation EC2:</strong> $(($suspiciousResources | Where-Object {$_.SuspiciousPattern -eq "Old Generation Instances"}).Count) instances using outdated types</li>
            </ol>
        </div>
    </div>
    
    <h2>🔍 Detailed Findings</h2>
    <table>
        <tr>
            <th>Risk</th>
            <th>Resource Name</th>
            <th>Type</th>
            <th>Region</th>
            <th>Issue Found</th>
            <th>Cost Impact</th>
            <th>Additional Info</th>
            <th>Tags</th>
        </tr>
"@

# Add table rows - prioritize orphaned volumes
$sortedResources = $suspiciousResources | Sort-Object @{Expression={if($_.SuspiciousPattern -eq "Orphaned Volume") {0} else {1}}}, RiskLevel, ResourceName

foreach ($resource in $sortedResources) {
    $riskClass = "risk-" + $resource.RiskLevel.ToLower()
    $rowClass = if ($resource.SuspiciousPattern -eq "Orphaned Volume") { "$riskClass orphan-highlight" } else { $riskClass }
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
        <h3>🎯 Quick Actions & AWS CLI Commands</h3>
        
        <h4>🗑️ Cleanup Commands (Use with caution!):</h4>
        <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px;">
# List all orphaned resources for review
aws ec2 describe-volumes --filters "Name=status,Values=available" --query "Volumes[?!Attachments].{VolumeId:VolumeId,Size:Size,VolumeType:VolumeType,CreateTime:CreateTime}"
aws ec2 describe-addresses --query "Addresses[?!AssociationId].{PublicIp:PublicIp,AllocationId:AllocationId}"
aws ec2 describe-network-interfaces --filters "Name=status,Values=available" --query "NetworkInterfaces[].{NetworkInterfaceId:NetworkInterfaceId,Description:Description}"

# Delete commands (VERIFY FIRST!)
# aws ec2 delete-volume --volume-id vol-xxxxxxxxx
# aws ec2 release-address --allocation-id eipalloc-xxxxxxxxx
# aws ec2 delete-network-interface --network-interface-id eni-xxxxxxxxx
# aws ec2 delete-security-group --group-id sg-xxxxxxxxx
# aws elb delete-load-balancer --load-balancer-name my-load-balancer
# aws elbv2 delete-load-balancer --load-balancer-arn arn:aws:elasticloadbalancing:...
        </pre>
        
        <h4>📊 Cost Analysis Commands:</h4>
        <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px;">
# Get actual cost data (requires Cost Explorer access)
aws ce get-cost-and-usage --time-period Start=2024-05-01,End=2024-06-01 --granularity MONTHLY --metrics BlendedCost --group-by Type=DIMENSION,Key=SERVICE

# Check resource creation dates and costs
aws ec2 describe-instances --query "Reservations[].Instances[?contains(Tags[?Key=='Name'].Value, 'test')].{InstanceId:InstanceId,InstanceType:InstanceType,LaunchTime:LaunchTime,Tags:Tags}" --output table

# List untagged resources
aws resourcegroupstaggingapi get-resources --resource-type-filters "AWS::EC2::Instance" "AWS::EC2::Volume" --tag-filters "Key=Environment" --query "ResourceTagMappingList[?!Tags]"
        </pre>
        
        <h4>🔧 Automation Scripts:</h4>
        <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px;">
# Create AWS Config rule for untagged resources
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "required-tags",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "REQUIRED_TAGS"
  },
  "InputParameters": "{\"tag1Key\":\"Environment\",\"tag2Key\":\"Owner\"}"
}'

# Set up cost budget alert
aws budgets create-budget --account-id YOUR_ACCOUNT_ID --budget '{
  "BudgetName": "Monthly-Cost-Budget",
  "BudgetLimit": {"Amount": "100", "Unit": "USD"},
  "TimeUnit": "MONTHLY",
  "BudgetType": "COST"
}'
        </pre>
        
        <div style="background: #ffebee; border: 1px solid #f44336; border-radius: 5px; padding: 10px; margin-top: 10px;">
            <p><strong>WARNING:</strong> Always verify resources are truly unused before deletion. Check with application owners and review dependencies! Some managed services create resources automatically.</p>
        </div>
    </div>
    
    <div class="tip">
        <h3>🛡️ AWS Security & Governance Best Practices</h3>
        <ul>
            <li><strong>🏷️ Implement mandatory tagging:</strong> Use AWS Config rules to enforce Environment, Owner, and Project tags</li>
            <li><strong>💰 Set up Cost Budgets:</strong> Create alerts when spending exceeds thresholds</li>
            <li><strong>📊 Use AWS Cost Explorer:</strong> Analyze spending patterns and identify cost anomalies</li>
            <li><strong>🔍 Enable AWS CloudTrail:</strong> Track resource creation and modification for audit trails</li>
            <li><strong>⚡ Implement lifecycle policies:</strong> Automate EBS snapshot cleanup and S3 object transitions</li>
            <li><strong>🎯 Use AWS Trusted Advisor:</strong> Get recommendations for cost optimization and security</li>
        </ul>
    </div>
    
    <div class="footer">
        <p>🤖 Generated by Enhanced Forgotten Resource Detective for AWS | Part of "FinOps for Everyone" series</p>
        <p>💡 <strong>Next Steps:</strong> Focus on orphaned EBS volumes first for immediate savings, then review load balancers and old snapshots</p>
        <p>🔄 <strong>Automation Tip:</strong> Consider using AWS Lambda functions to automatically detect and alert on orphaned resources</p>
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
Write-Host "`nEnhanced AWS report generated successfully!" -ForegroundColor Green
Write-Host "HTML Report: $OutputPath"              -ForegroundColor Cyan
Write-Host "CSV Export: $CsvOutputPath"          -ForegroundColor Cyan

# Risk distribution counts
$highCount = ($suspiciousResources | Where-Object { $_.RiskLevel -eq 'High'   }).Count
$medCount  = ($suspiciousResources | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
$lowCount  = ($suspiciousResources | Where-Object { $_.RiskLevel -eq 'Low'    }).Count

Write-Host "`nQuick Summary:"                   -ForegroundColor Magenta
Write-Host "Potential monthly savings: $([Math]::Round($totalEstimatedSavings,2)) USD" -ForegroundColor Green
Write-Host "Critical Issues:"                  -ForegroundColor Red
Write-Host "   Orphaned EBS Volumes: $($orphanedVolumes.Count)" -ForegroundColor White
Write-Host "   Orphaned ENIs: $($orphanedENIs.Count)" -ForegroundColor White
Write-Host "   Unattached Elastic IPs: $($unattachedEIPs.Count)" -ForegroundColor White
Write-Host "   Suspicious Load Balancers: $(($suspiciousClassicLBs.Count + $suspiciousApplicationLBs.Count))" -ForegroundColor White
Write-Host "   Unused Security Groups: $($unusedSecurityGroups.Count)" -ForegroundColor White
Write-Host "   Unused Key Pairs: $($unusedKeyPairs.Count)" -ForegroundColor White
Write-Host "   Old Snapshots (>$DaysThreshold days): $($oldSnapshots.Count)" -ForegroundColor White

Write-Host "`nRisk Distribution:"               -ForegroundColor Yellow
Write-Host "   High Risk:   $highCount resources"   -ForegroundColor Red
Write-Host "   Medium Risk: $medCount resources"    -ForegroundColor Yellow
Write-Host "   Low Risk:    $lowCount resources"    -ForegroundColor Green

Write-Host "`nRecommended Actions:"           -ForegroundColor Cyan
Write-Host "1. Delete orphaned EBS volumes and release unattached Elastic IPs" -ForegroundColor White
Write-Host "2. Review load balancers with no healthy targets"        -ForegroundColor White
Write-Host "3. Clean up unused security groups and key pairs"            -ForegroundColor White
Write-Host "4. Implement mandatory tagging with AWS Config rules"     -ForegroundColor White
Write-Host "5. Set up AWS Budgets and Cost Explorer for ongoing monitoring"            -ForegroundColor White
Write-Host "6. Review and delete old EBS snapshots older than $DaysThreshold days"     -ForegroundColor White

Write-Host "`n💡 Pro Tips:"                    -ForegroundColor Yellow
Write-Host "- Use AWS Systems Manager to automate cleanup tasks" -ForegroundColor Gray
Write-Host "- Set up CloudWatch Events to alert on untagged resource creation" -ForegroundColor Gray
Write-Host "- Consider using AWS Resource Groups for better resource organization" -ForegroundColor Gray
Write-Host "- Enable AWS Cost Anomaly Detection for unusual spending patterns" -ForegroundColor Gray
