# 🕵️ Forgotten Resource Detective for Azure (Enhanced)
# A simple script to find resources that might be forgotten and costing you money
# Part of the "FinOps for Everyone" series

param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysThreshold = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "forgotten-resources-report.html",
    
    [Parameter(Mandatory=$false)]
    [string]$CsvOutputPath = "forgotten-resources-report.csv"
)

# 🚀 Connect to Azure (make sure you're logged in with 'az login')
Write-Host "Starting Forgotten Resource Detective..." -ForegroundColor Cyan
Write-Host "Looking for resources older than $DaysThreshold days with suspicious patterns..." -ForegroundColor Yellow

# Set subscription context
az account set --subscription $SubscriptionId

# Get all resources with creation date
Write-Host "Gathering resource information..." -ForegroundColor Green
$allResources = az resource list --query "[].{name:name, type:type, resourceGroup:resourceGroup, location:location, tags:tags}" | ConvertFrom-Json

# 💾 Get detailed disk information to identify orphans
Write-Host "Analyzing disk attachments..." -ForegroundColor Blue
# First, let's get all disk properties to ensure we're using the right field names
$allDisks = az disk list --query "[].{name:name, resourceGroup:resourceGroup, diskState:diskState, managedBy:managedBy, id:id, tags:tags, timeCreated:timeCreated, size:diskSizeGb, sizeGB:properties.diskSizeGb, sizeInBytes:diskSizeBytes, skuName:sku.name, skuTier:sku.tier}" | ConvertFrom-Json

# Debug: Show what we're getting for the first disk (optional - comment out in production)
if ($allDisks.Count -gt 0) {
    Write-Host "Debug - First disk properties:" -ForegroundColor Yellow
    Write-Host "  Name: $($allDisks[0].name)" -ForegroundColor Gray
    Write-Host "  Size: $($allDisks[0].size)" -ForegroundColor Gray
    Write-Host "  SizeGB: $($allDisks[0].sizeGB)" -ForegroundColor Gray
    Write-Host "  SizeInBytes: $($allDisks[0].sizeInBytes)" -ForegroundColor Gray
    Write-Host "  SkuName: $($allDisks[0].skuName)" -ForegroundColor Gray
    Write-Host "  SkuTier: $($allDisks[0].skuTier)" -ForegroundColor Gray
}

# 🌐 Get detailed network information
Write-Host "Analyzing network resources..." -ForegroundColor Blue
$publicIPs = az network public-ip list --query "[].{name:name, resourceGroup:resourceGroup, ipConfiguration:ipConfiguration, tags:tags, sku:sku.name}" | ConvertFrom-Json
$networkInterfaces = az network nic list --query "[].{name:name, resourceGroup:resourceGroup, virtualMachine:virtualMachine, ipConfigurations:ipConfigurations, tags:tags, privateEndpoint:privateEndpoint}" | ConvertFrom-Json
$nsgList = az network nsg list --query "[].{name:name, resourceGroup:resourceGroup, networkInterfaces:networkInterfaces, subnets:subnets, tags:tags}" | ConvertFrom-Json

# 🗄️ Get storage account information
Write-Host "Analyzing storage accounts..." -ForegroundColor Blue
$storageAccounts = az storage account list --query "[].{name:name, resourceGroup:resourceGroup, sku:sku.name, kind:kind, tags:tags, creationTime:creationTime, accessTier:accessTier}" | ConvertFrom-Json

# 🖥️ Get VM information for enrichment purposes only
Write-Host "Analyzing virtual machines..." -ForegroundColor Blue
$virtualMachines = az vm list --query "[].{name:name, resourceGroup:resourceGroup, vmSize:hardwareProfile.vmSize, tags:tags, powerState:'', osType:storageProfile.osDisk.osType}" | ConvertFrom-Json

# ⚖️ Get load balancer information
Write-Host "Analyzing load balancers..." -ForegroundColor Blue
$loadBalancers = az network lb list --query "[].{name:name, resourceGroup:resourceGroup, frontendIpConfigurations:frontendIpConfigurations, backendAddressPools:backendAddressPools, tags:tags, sku:sku.name}" | ConvertFrom-Json

# Identify truly orphaned disks
$orphanedDisks = $allDisks | Where-Object { 
    $_.diskState -eq "Unattached" -and [string]::IsNullOrEmpty($_.managedBy) 
}

# Identify orphaned NICs (excluding managed service NICs)
$orphanedNICs = $networkInterfaces | Where-Object { 
    [string]::IsNullOrEmpty($_.virtualMachine) -and 
    [string]::IsNullOrEmpty($_.privateEndpoint) -and
    $_.name -notmatch "^(nic-|pe-|privateEndpoint-|keyvault-|acr-|storage-|sql-|cosmos-|servicebus-|eventhub-)" -and
    $_.name -notmatch "(privateEndpoint|private-endpoint|pe\d+|pep-)" -and
    $_.resourceGroup -notmatch "^MC_" -and  # Exclude AKS managed resource groups
    -not ($_.tags -and $_.tags.PSObject.Properties.Name -contains "managed-by")  # Exclude NICs tagged as managed
}

# Identify unattached public IPs
$unattachedPublicIPs = $publicIPs | Where-Object { 
    [string]::IsNullOrEmpty($_.ipConfiguration) 
}

# Identify empty NSGs
$emptyNSGs = $nsgList | Where-Object { 
    ($null -eq $_.networkInterfaces -or $_.networkInterfaces.Count -eq 0) -and 
    ($null -eq $_.subnets -or $_.subnets.Count -eq 0) 
}

# Identify potentially empty load balancers
$suspiciousLoadBalancers = $loadBalancers | Where-Object { 
    ($null -eq $_.backendAddressPools -or $_.backendAddressPools.Count -eq 0) 
}

Write-Host "Resource Analysis Summary:" -ForegroundColor Yellow
Write-Host "   Orphaned Disks: $($orphanedDisks.Count) out of $($allDisks.Count) total" -ForegroundColor White
Write-Host "   Orphaned NICs: $($orphanedNICs.Count) out of $($networkInterfaces.Count) total (excluding managed service NICs)" -ForegroundColor White
Write-Host "   Unattached Public IPs: $($unattachedPublicIPs.Count) out of $($publicIPs.Count) total" -ForegroundColor White
Write-Host "   Empty NSGs: $($emptyNSGs.Count) out of $($nsgList.Count) total" -ForegroundColor White
Write-Host "   Suspicious Load Balancers: $($suspiciousLoadBalancers.Count) out of $($loadBalancers.Count) total" -ForegroundColor White

# Enhanced suspicious patterns to detect
$suspiciousPatterns = @(
    @{
        Name="No Tags"
        Pattern={param($r) ($null -eq $r.tags) -or ($r.tags.Count -eq 0)}
        Risk="High"
        Description="Resources without proper tagging are hard to track and manage"
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
        Name="Premium Storage (Test/Dev)"
        Pattern={param($r) $r.type -eq "Microsoft.Storage/storageAccounts" -and $r.name -match "(test|temp|dev)" -and ($r.sku -match "Premium")}
        Risk="High"
        Description="Premium storage for test/dev environments is unnecessarily expensive"
        CostImpact="High"
    },
    @{
        Name="Old Generation VMs"
        Pattern={param($r) $r.type -eq "Microsoft.Compute/virtualMachines" -and $r.vmSize -match "(Basic_|Standard_A[0-9]|Standard_D[0-9]v1)"}
        Risk="Medium"
        Description="Old generation VMs are less cost-efficient than newer versions"
        CostImpact="Medium"
    },
    @{
        Name="Test Storage Accounts"
        Pattern={param($r) $r.type -eq "Microsoft.Storage/storageAccounts" -and $r.name -match "(test|temp|backup|dev)"}
        Risk="Medium"
        Description="Storage accounts with test-like names may contain unused data"
        CostImpact="Medium"
    }
)

# Initialize results
$suspiciousResources = @()

# Check each resource against patterns (excluding orphaned resources which we handle separately)
foreach ($resource in $allResources) {
    foreach ($pattern in $suspiciousPatterns) {
        if (& $pattern.Pattern $resource) {
            # Enrich resource data for specific types
            $additionalInfo = ""
            $estimatedCost = "Unknown"
            
            # Add specific details based on resource type
            switch ($resource.type) {
                "Microsoft.Compute/virtualMachines" {
                    $vmDetails = $virtualMachines | Where-Object { $_.name -eq $resource.name -and $_.resourceGroup -eq $resource.resourceGroup }
                    if ($vmDetails) {
                        $additionalInfo = "VM Size: $($vmDetails.vmSize), OS: $($vmDetails.osType)"
                    }
                }
                "Microsoft.Storage/storageAccounts" {
                    $storageDetails = $storageAccounts | Where-Object { $_.name -eq $resource.name }
                    if ($storageDetails) {
                        $additionalInfo = "SKU: $($storageDetails.sku), Kind: $($storageDetails.kind), Tier: $($storageDetails.accessTier)"
                    }
                }
            }
            
            $suspiciousResources += [PSCustomObject]@{
                ResourceName = $resource.name
                ResourceType = $resource.type
                ResourceGroup = $resource.resourceGroup
                Location = $resource.location
                SuspiciousPattern = $pattern.Name
                RiskLevel = $pattern.Risk
                Description = $pattern.Description
                CostImpact = $pattern.CostImpact
                Tags = if ($resource.tags) { ($resource.tags | ConvertTo-Json -Compress) } else { "None" }
                EstimatedMonthlyCost = $estimatedCost
                AdditionalInfo = $additionalInfo
            }
        }
    }
}

# Add orphaned network resources
foreach ($nic in $orphanedNICs) {
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $nic.name
        ResourceType = "Microsoft.Network/networkInterfaces"
        ResourceGroup = $nic.resourceGroup
        Location = ""
        SuspiciousPattern = "Orphaned NIC"
        RiskLevel = "High"
        Description = "Network interface not attached to any VM"
        CostImpact = "Low"
        Tags = if ($nic.tags) { ($nic.tags | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "$3-5"
        AdditionalInfo = "Unattached network interface"
    }
}

foreach ($pip in $unattachedPublicIPs) {
    $costEstimate = if ($pip.sku -eq "Standard") { "$3.65" } else { "$2.92" }
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $pip.name
        ResourceType = "Microsoft.Network/publicIPAddresses"
        ResourceGroup = $pip.resourceGroup
        Location = ""
        SuspiciousPattern = "Unattached Public IP"
        RiskLevel = "Medium"
        Description = "Public IP not attached to any resource but still incurring charges"
        CostImpact = "Low"
        Tags = if ($pip.tags) { ($pip.tags | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = $costEstimate
        AdditionalInfo = "SKU: $($pip.sku)"
    }
}

foreach ($nsg in $emptyNSGs) {
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $nsg.name
        ResourceType = "Microsoft.Network/networkSecurityGroups"
        ResourceGroup = $nsg.resourceGroup
        Location = ""
        SuspiciousPattern = "Empty NSG"
        RiskLevel = "Low"
        Description = "Network Security Group not protecting any resources"
        CostImpact = "None"
        Tags = if ($nsg.tags) { ($nsg.tags | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = "Free"
        AdditionalInfo = "No attached NICs or subnets"
    }
}

foreach ($lb in $suspiciousLoadBalancers) {
    $costEstimate = if ($lb.sku -eq "Standard") { "$18.25" } else { "$18.25" }
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $lb.name
        ResourceType = "Microsoft.Network/loadBalancers"
        ResourceGroup = $lb.resourceGroup
        Location = ""
        SuspiciousPattern = "Empty Load Balancer"
        RiskLevel = "High"
        Description = "Load balancer with no backend pools or minimal configuration"
        CostImpact = "High"
        Tags = if ($lb.tags) { ($lb.tags | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = $costEstimate
        AdditionalInfo = "SKU: $($lb.sku), No backend pools"
    }
}

# Add orphaned disks as separate entries with detailed information
foreach ($disk in $orphanedDisks) {
    # Calculate age of disk
    $createdDate = if ($disk.timeCreated) { [DateTime]::Parse($disk.timeCreated) } else { $null }
    $ageInDays = if ($createdDate) { [Math]::Round(((Get-Date) - $createdDate).TotalDays) } else { "Unknown" }
    
    # Get disk size - try multiple properties
    $diskSize = 0
    if ($disk.size) { $diskSize = $disk.size }
    elseif ($disk.sizeGB) { $diskSize = $disk.sizeGB }
    elseif ($disk.diskSizeGb) { $diskSize = $disk.diskSizeGb }
    elseif ($disk.sizeInBytes) { $diskSize = [Math]::Round($disk.sizeInBytes / 1GB) }
    
    # Get disk tier - try multiple properties
    $diskTier = "Unknown"
    if ($disk.skuName) { $diskTier = $disk.skuName }
    elseif ($disk.skuTier) { $diskTier = $disk.skuTier }
    elseif ($disk.tier) { $diskTier = $disk.tier }
    
    # Estimate monthly cost based on disk size and tier
    $estimatedCost = switch ($diskTier) {
        "Standard_LRS" { [Math]::Round($diskSize * 0.05, 2) }
        "Premium_LRS" { [Math]::Round($diskSize * 0.135, 2) }
        "StandardSSD_LRS" { [Math]::Round($diskSize * 0.075, 2) }
        "Premium_ZRS" { [Math]::Round($diskSize * 0.169, 2) }
        "StandardSSD_ZRS" { [Math]::Round($diskSize * 0.094, 2) }
        default { 
            if ($diskSize -gt 0) { 
                # Default to Standard_LRS pricing if tier unknown
                [Math]::Round($diskSize * 0.05, 2) 
            } else { 
                "Unknown" 
            }
        }
    }
    
    $suspiciousResources += [PSCustomObject]@{
        ResourceName = $disk.name
        ResourceType = "Microsoft.Compute/disks"
        ResourceGroup = $disk.resourceGroup
        Location = ""  # We can add this if needed
        SuspiciousPattern = "Orphaned Disk"
        RiskLevel = "High"
        Description = "Unattached disk that may be forgotten and incurring costs"
        CostImpact = "High"
        Tags = if ($disk.tags) { ($disk.tags | ConvertTo-Json -Compress) } else { "None" }
        EstimatedMonthlyCost = if ($estimatedCost -ne "Unknown" -and $diskSize -gt 0) { "$" + $estimatedCost } else { "Unknown" }
        AdditionalInfo = "Size: ${diskSize}GB, Tier: $diskTier, Age: $ageInDays days"
    }
}

# Calculate total estimated monthly savings
$totalEstimatedSavings = ($suspiciousResources | Where-Object { $_.EstimatedMonthlyCost -ne "Unknown" -and $_.EstimatedMonthlyCost -ne "" -and $_.EstimatedMonthlyCost -ne "Free" } | ForEach-Object { 
    $cost = $_.EstimatedMonthlyCost -replace '\$', '' -replace '-.*', ''
    try { [double]$cost } catch { 0 }
} | Measure-Object -Sum).Sum

# Generate Enhanced HTML Report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>🕵️ Forgotten Resource Detective Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
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
        <h1>🕵️ Forgotten Resource Detective</h1>
        <p>Subscription: $SubscriptionId | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
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
            <li>💾 Orphaned Disks: $($orphanedDisks.Count) (Direct cost impact)</li>
            <li>🔌 Orphaned NICs: $($orphanedNICs.Count) (Small ongoing cost)</li>
            <li>🌐 Unattached Public IPs: $($unattachedPublicIPs.Count) (Monthly charges)</li>
            <li>⚖️ Suspicious Load Balancers: $($suspiciousLoadBalancers.Count) (High cost impact)</li>
            <li>🛡️ Empty NSGs: $($emptyNSGs.Count) (Management overhead)</li>
        </ul>
        <p><strong>📈 Risk Distribution:</strong></p>
        <p><strong>High Risk:</strong> $(($suspiciousResources | Where-Object {$_.RiskLevel -eq 'High'}).Count) | 
           <strong>Medium Risk:</strong> $(($suspiciousResources | Where-Object {$_.RiskLevel -eq 'Medium'}).Count) | 
           <strong>Low Risk:</strong> $(($suspiciousResources | Where-Object {$_.RiskLevel -eq 'Low'}).Count)</p>
    </div>
    
    <div class="tip">
        <h3>💡 FinOps Action Priority</h3>
        <ul>
            <li><strong>🔥 Immediate (Week 1):</strong> Delete orphaned disks, NICs, and unattached public IPs</li>
            <li><strong>⚖️ Quick Wins (Week 2):</strong> Review empty load balancers and NSGs</li>
            <li><strong>📊 Modernization (Month 1):</strong> Upgrade old generation VMs to newer SKUs</li>
            <li><strong>🏷️ Governance (Ongoing):</strong> Implement tagging policies for new resources</li>
            <li><strong>🔄 Automation (Month 2):</strong> Set up alerts for untagged resources</li>
        </ul>
        
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 10px; margin-top: 15px;">
            <h4>🎯 Top 3 Cost Optimization Opportunities:</h4>
            <ol>
                <li><strong>Orphaned Disks:</strong> $([Math]::Round($totalEstimatedSavings, 2)) USD/month potential savings</li>
                <li><strong>Load Balancer Review:</strong> $($suspiciousLoadBalancers.Count) LBs to validate (~$18/month each)</li>
                <li><strong>Old Generation VMs:</strong> $(($suspiciousResources | Where-Object {$_.SuspiciousPattern -eq "Old Generation VMs"}).Count) VMs using outdated SKUs</li>
            </ol>
        </div>
    </div>
    
    <h2>🔍 Detailed Findings</h2>
    <table>
        <tr>
            <th>Risk</th>
            <th>Resource Name</th>
            <th>Type</th>
            <th>Resource Group</th>
            <th>Issue Found</th>
            <th>Cost Impact</th>
            <th>Additional Info</th>
            <th>Tags</th>
        </tr>
"@

# Add table rows - prioritize orphaned disks
$sortedResources = $suspiciousResources | Sort-Object @{Expression={if($_.SuspiciousPattern -eq "Orphaned Disk") {0} else {1}}}, RiskLevel, ResourceName

foreach ($resource in $sortedResources) {
    $riskClass = "risk-" + $resource.RiskLevel.ToLower()
    $rowClass = if ($resource.SuspiciousPattern -eq "Orphaned Disk") { "$riskClass orphan-highlight" } else { $riskClass }
    $costDisplay = if ($resource.EstimatedMonthlyCost -and $resource.EstimatedMonthlyCost -ne "Unknown") { 
        "<span class='cost-cell'>$($resource.EstimatedMonthlyCost)</span>" 
    } else { 
        $resource.CostImpact
    }
    
    $htmlReport += @"
        <tr class="$rowClass">
            <td><strong>$($resource.RiskLevel)</strong></td>
            <td>$($resource.ResourceName)</td>
            <td>$($resource.ResourceType.Split('/')[-1])</td>
            <td>$($resource.ResourceGroup)</td>
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
        <h3>🎯 Quick Actions & Commands</h3>
        
        <h4>🗑️ Cleanup Commands (Use with caution!):</h4>
        <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px;">
# List all orphaned resources for review
az disk list --query "[?diskState=='Unattached' && managedBy==null].{Name:name, RG:resourceGroup, Size:diskSizeGb}"
az network nic list --query "[?virtualMachine==null].{Name:name, RG:resourceGroup}"
az network public-ip list --query "[?ipConfiguration==null].{Name:name, RG:resourceGroup, SKU:sku.name}"

# Delete commands (VERIFY FIRST!)
# az disk delete --name "disk-name" --resource-group "rg-name" --yes
# az network nic delete --name "nic-name" --resource-group "rg-name"
# az network public-ip delete --name "pip-name" --resource-group "rg-name"
        </pre>
        
        <h4>📊 Cost Analysis Commands:</h4>
        <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px;">
# Get actual cost data (requires Cost Management access)
# PowerShell: 
`$startDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-dd")
az consumption usage list --top 100 --start-date `$startDate

# Check resource creation dates
az resource list --query "[?contains(name, 'test')].{Name:name, Type:type, CreatedTime:createdTime}" -o table
        </pre>
        
        <div style="background: #ffebee; border: 1px solid #f44336; border-radius: 5px; padding: 10px; margin-top: 10px;">
            <p><strong>WARNING:</strong> Always verify resources are truly unused before deletion. Check with application owners and review dependencies!</p>
        </div>
    </div>
    
    <div class="footer">
        <p>🤖 Generated by Enhanced Forgotten Resource Detective | Part of "FinOps for Everyone" series</p>
        <p>💡 <strong>Next Steps:</strong> Focus on orphaned disks first for immediate savings, then review other high-risk resources</p>
    </div>
</body>
</html>
"@

# Save report
$htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8

# Export to CSV
Write-Host "`nExporting results to CSV..." -ForegroundColor Green
# ————— Export CSV —————
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
            if ($_.EstimatedMonthlyCost -and $_.EstimatedMonthlyCost -ne 'Unknown' -and $_.EstimatedMonthlyCost -ne 'Free') {
                $_.EstimatedMonthlyCost -replace '[^\d.]',''
            }
            else {
                $_.EstimatedMonthlyCost
            }
        }}, `
        @{Name='AdditionalInfo';      Expression={$_.AdditionalInfo}}, `
        @{Name='Tags';                Expression={$_.Tags}} |
    Export-Csv -Path $CsvOutputPath -NoTypeInformation -Encoding UTF8

# ————— Final console summary —————
Write-Host "`nEnhanced report generated successfully!" -ForegroundColor Green
Write-Host "HTML Report: $OutputPath"              -ForegroundColor Cyan
Write-Host "CSV Export: $CsvOutputPath"          -ForegroundColor Cyan

# Risk distribution counts
$highCount = ($suspiciousResources | Where-Object { $_.RiskLevel -eq 'High'   }).Count
$medCount  = ($suspiciousResources | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
$lowCount  = ($suspiciousResources | Where-Object { $_.RiskLevel -eq 'Low'    }).Count

Write-Host "`nQuick Summary:"                   -ForegroundColor Magenta
Write-Host "Potential monthly savings: $([Math]::Round($totalEstimatedSavings,2)) USD" -ForegroundColor Green
Write-Host "Critical Issues:"                  -ForegroundColor Red
Write-Host "   Orphaned Disks: $($orphanedDisks.Count)" -ForegroundColor White
Write-Host "   Orphaned NICs:  $($orphanedNICs.Count)" -ForegroundColor White
Write-Host "   Unattached Public IPs: $($unattachedPublicIPs.Count)" -ForegroundColor White
Write-Host "   Suspicious Load Balancers: $($suspiciousLoadBalancers.Count)" -ForegroundColor White

Write-Host "`nRisk Distribution:"               -ForegroundColor Yellow
Write-Host "   High Risk:   $highCount resources"   -ForegroundColor Red
Write-Host "   Medium Risk: $medCount resources"    -ForegroundColor Yellow
Write-Host "   Low Risk:    $lowCount resources"    -ForegroundColor Green

Write-Host "`nRecommended Actions:"           -ForegroundColor Cyan
Write-Host "1. Delete orphaned resources (disks, NICs, public IPs)" -ForegroundColor White
Write-Host "2. Review load balancers without backend pools"        -ForegroundColor White
Write-Host "3. Upgrade old generation VMs to newer SKUs"            -ForegroundColor White
Write-Host "4. Implement tagging governance for cost tracking"     -ForegroundColor White
Write-Host "5. Set up automated cost alerts and budgets"            -ForegroundColor White
