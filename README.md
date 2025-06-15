# 🕵️ Forgotten Resource Detective - Multi-Cloud Edition

> **Part of the "FinOps for Everyone" series**

A collection of scripts to hunt down forgotten, orphaned, and suspicious cloud resources across Azure, AWS, GCP, and OCI that might be silently draining your cloud budget. These detective tools help you identify cost optimization opportunities and improve cloud governance.

## 🌟 **What Does It Do?**

Each script scans your cloud environment to identify:

- 💾 **Orphaned Storage** - Unattached disks/volumes costing money
- 🌐 **Unattached IPs** - Reserved but unused public IP addresses
- 🔌 **Orphaned Network Interfaces** - Detached network components
- ⚖️ **Empty Load Balancers** - Load balancers with no backends
- 🛡️ **Unused Security Groups/Rules** - Security configurations protecting nothing
- 👴 **Legacy Resources** - Old generation instances/types
- 🏷️ **Untagged Resources** - Resources without proper cost tracking labels
- 🚩 **Suspicious Names** - Resources with test/temp/demo naming patterns

## 📋 **Cloud Provider Coverage**

| Cloud Provider | Language | Script Name | Status |
|---------------|----------|-------------|---------|
| **Microsoft Azure** | PowerShell | `azure-forgotten-resources.ps1` | ✅ Complete |
| **Amazon AWS** | PowerShell | `aws-forgotten-resources.ps1` | ✅ Complete |
| **Google Cloud Platform** | PowerShell | `gcp-forgotten-resources.ps1` | ✅ Complete |
| **Oracle Cloud Infrastructure** | Python | `oci_forgotten_resources.py` | ✅ Complete |

## 🚀 **Quick Start**

### **Azure (PowerShell)**
```powershell
# Basic usage
.\azure-forgotten-resources.ps1 -SubscriptionId "your-subscription-id"

# Advanced usage with custom thresholds
.\azure-forgotten-resources.ps1 -SubscriptionId "your-sub-id" -DaysThreshold 60 -OutputPath "azure-report.html"
```

### **AWS (PowerShell)**
```powershell
# Basic usage
.\aws-forgotten-resources.ps1 -Region "us-east-1"

# With specific AWS profile and custom settings
.\aws-forgotten-resources.ps1 -Region "us-west-2" -ProfileName "production" -DaysThreshold 90
```

### **GCP (PowerShell)**
```powershell
# Basic usage
.\gcp-forgotten-resources.ps1 -ProjectId "my-production-project"

# With specific region and custom output
.\gcp-forgotten-resources.ps1 -ProjectId "my-project" -Region "us-central1" -OutputPath "gcp-report.html"
```

### **OCI (Python)**
```bash
# Basic usage
python oci_forgotten_resources.py --profile DEFAULT

# Advanced usage with custom patterns
python oci_forgotten_resources.py \
  --profile PRODUCTION \
  --old-shape-pattern "VM\.Standard1.*" \
  --output-html oci_report.html \
  --output-csv oci_data.csv
```

## 📊 **Sample Output**

Each script generates:

1. **📈 HTML Report** - Beautiful, executive-friendly dashboard with:
   - Cost savings summary
   - Risk distribution charts
   - Detailed findings table
   - Actionable cleanup commands
   - Best practices recommendations

2. **📁 CSV Export** - Machine-readable data for:
   - Further analysis in Excel/BI tools
   - Integration with ITSM systems
   - Automated processing workflows

3. **💰 Cost Estimates** - Realistic monthly savings calculations

## 🛠️ **Prerequisites**

### **Azure**
- Azure CLI installed and configured (`az login`)
- PowerShell 5.1+ or PowerShell Core
- Appropriate Azure RBAC permissions (Reader + Cost Management Reader)

### **AWS**
- AWS CLI installed and configured (`aws configure`)
- PowerShell 5.1+ or PowerShell Core
- IAM permissions for EC2, ELB, S3, Cost Explorer

### **GCP**
- Google Cloud SDK installed and configured (`gcloud auth login`)
- PowerShell 5.1+ or PowerShell Core
- IAM permissions for Compute Engine, Cloud SQL, Cloud Storage, Billing

### **OCI**
- OCI CLI configured (`~/.oci/config`)
- Python 3.6+ with `oci` SDK installed (`pip install oci`)
- OCI IAM permissions for Compute, Block Storage, Networking, Load Balancer

## 🎯 **Resource Detection Matrix**

| Resource Type | Azure | AWS | GCP | OCI |
|--------------|--------|-----|-----|-----|
| **Unattached Disks/Volumes** | ✅ Managed Disks | ✅ EBS Volumes | ✅ Persistent Disks | ✅ Block Volumes |
| **Unattached Public IPs** | ✅ Public IPs | ✅ Elastic IPs | ✅ Static IPs | ✅ Reserved Public IPs |
| **Orphaned Network Interfaces** | ✅ NICs | ✅ ENIs | ✅ (via instances) | ✅ (via VNICs) |
| **Empty Load Balancers** | ✅ Load Balancers | ✅ ALB/NLB/CLB | ✅ Backend Services | ✅ Load Balancers |
| **Unused Security Groups** | ✅ NSGs | ✅ Security Groups | ✅ Firewall Rules | ✅ Network Security Groups |
| **Legacy Compute** | ✅ Old VM Sizes | ✅ Old Instance Types | ✅ Legacy Machine Types | ✅ Old Shapes |
| **Old Snapshots/Images** | ❌ | ✅ EBS Snapshots | ✅ Snapshots & Images | ❌ |
| **Unused Key Pairs** | ❌ | ✅ EC2 Key Pairs | ❌ | ❌ |
| **Cloud Databases** | ❌ | ❌ | ✅ Cloud SQL | ❌ |
| **Storage Buckets** | ✅ Storage Accounts | ✅ S3 Buckets | ✅ Cloud Storage | ❌ |

## 💡 **Cost Optimization Impact**

### **Typical Monthly Savings by Resource Type:**

| Resource Type | Azure | AWS | GCP | OCI |
|--------------|--------|-----|-----|-----|
| **100GB Unattached Disk** | ~$5 | ~$8-10 | ~$4-17 | ~$2.50 |
| **Unattached Public IP** | ~$3 | ~$3.65 | ~$1.46 | ~$3.65 |
| **Empty Load Balancer** | ~$18 | ~$16-18 | ~$16 | ~$18 |
| **Legacy Instance (Small)** | 10-30% | 10-30% | 10-30% | 10-30% |
| **Old Snapshot (100GB)** | N/A | ~$5 | ~$2.60 | N/A |

## 🔧 **Advanced Usage**

### **Custom Suspicious Patterns**
```powershell
# Azure/AWS/GCP - Modify the $suspiciousPatterns array in the script
$suspiciousPatterns = @(
    @{
        Name="Custom Pattern"
        Pattern={param($r) $r.name -match "your-custom-regex"}
        Risk="High"
        Description="Your custom detection logic"
        CostImpact="High"
    }
)
```

```python
# OCI - Modify the suspicious_name_regex parameter
python oci_forgotten_resources.py \
  --suspicious-name-regex "\b(staging|qa|development|sandbox)\b"
```

### **Automation Integration**
```bash
# Run in CI/CD pipeline
./azure-forgotten-resources.ps1 -SubscriptionId $SUB_ID -OutputPath "artifacts/azure-report.html"

# Schedule with cron
0 6 * * 1 python oci_forgotten_resources.py --profile PROD --output-html weekly-report.html
```

## 🏷️ **Tagging/Labeling Best Practices**

Each script identifies untagged resources. Implement these mandatory tags/labels:

| Tag/Label | Purpose | Example Values |
|-----------|---------|----------------|
| **Environment** | Lifecycle stage | `production`, `staging`, `development` |
| **Owner** | Responsible team | `team-alpha`, `john.doe@company.com` |
| **Project** | Cost center | `project-phoenix`, `mobile-app` |
| **CostCenter** | Billing allocation | `IT-001`, `Marketing-002` |
| **AutoShutdown** | Automation hint | `yes`, `weekends-only`, `never` |

## 🔄 **Cleanup Commands Reference**

### **Azure**
```powershell
# Delete orphaned resources (VERIFY FIRST!)
az disk delete --name "disk-name" --resource-group "rg-name" --yes
az network public-ip delete --name "pip-name" --resource-group "rg-name"
az network nic delete --name "nic-name" --resource-group "rg-name"
```

### **AWS**
```bash
# Delete orphaned resources (VERIFY FIRST!)
aws ec2 delete-volume --volume-id vol-xxxxxxxxx
aws ec2 release-address --allocation-id eipalloc-xxxxxxxxx
aws ec2 delete-network-interface --network-interface-id eni-xxxxxxxxx
```

### **GCP**
```bash
# Delete orphaned resources (VERIFY FIRST!)
gcloud compute disks delete DISK_NAME --zone=ZONE_NAME --quiet
gcloud compute addresses delete ADDRESS_NAME --region=REGION_NAME --quiet
gcloud compute snapshots delete SNAPSHOT_NAME --quiet
```

### **OCI**
```bash
# Delete orphaned resources (VERIFY FIRST!)
oci bv volume delete --volume-id ocid1.volume.oc1...
oci network public-ip delete --public-ip-id ocid1.publicip.oc1...
```

## 🛡️ **Safety Guidelines**

⚠️ **ALWAYS verify before deletion:**

1. **Check dependencies** - Some resources may be used by applications not visible to the script
2. **Confirm with owners** - Reach out to teams before deleting their resources
3. **Backup critical data** - Take snapshots of important volumes before deletion
4. **Test in non-production** - Run cleanup commands in dev/staging first
5. **Use dry-run modes** - Many CLI commands support `--dry-run` flags

## 📈 **Governance & Automation**

### **Policy Implementation**
- **Azure**: Use Azure Policy for mandatory tagging
- **AWS**: Implement Config Rules for compliance
- **GCP**: Use Organization Policies for governance
- **OCI**: Set up IAM policies and compartment structures

### **Monitoring & Alerting**
- Set up budget alerts when spending exceeds thresholds
- Create automated reports using CI/CD pipelines
- Implement cost anomaly detection
- Use cloud-native monitoring for resource utilization

## 🤝 **Contributing**

We welcome contributions! Please:

1. Fork the repository
2. Create feature branches for new cloud providers or detection patterns
3. Add comprehensive comments explaining detection logic
4. Test thoroughly in sandbox environments
5. Submit pull requests with clear descriptions

### **Adding New Detection Patterns**
```powershell
# Template for new suspicious pattern
@{
    Name="Your Pattern Name"
    Pattern={param($r) $r.property -match "your-regex"}
    Risk="High|Medium|Low"
    Description="What this pattern detects and why it's risky"
    CostImpact="High|Medium|Low|None"
}
```

## 📚 **Additional Resources**

### **FinOps Learning**
- [FinOps Foundation](https://www.finops.org/)
- [Cloud Cost Optimization Best Practices](https://docs.microsoft.com/azure/cost-management/)
- [AWS Cost Optimization](https://aws.amazon.com/aws-cost-management/)
- [GCP Cost Management](https://cloud.google.com/cost-management)

### **Automation Tools**
- **Azure**: Azure Resource Graph, Azure Automation
- **AWS**: AWS Config, AWS Systems Manager
- **GCP**: Cloud Asset Inventory, Cloud Scheduler
- **OCI**: Resource Manager, Functions

## 🐛 **Troubleshooting**

### **Common Issues**

**"Permission Denied"**
- Ensure your account has appropriate read permissions
- Check if MFA is enabled and you're authenticated
- Verify cross-region access permissions

**"No Resources Found"**
- Confirm you're scanning the correct subscription/project/region
- Check if resources exist in different availability zones
- Verify the account has access to the target resources

**"Script Execution Error"**
- PowerShell: Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
- Python: Install missing dependencies with `pip install oci`
- Check cloud CLI authentication status

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- Inspired by the FinOps community's focus on cloud cost optimization
- Built for cloud engineers, platform teams, and finance professionals
- Special thanks to all contributors and testers

---

**⭐ Star this repository if it helps you save money on your cloud bill!**

*Happy hunting! 🕵️‍♂️💰*
