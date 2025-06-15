#!/usr/bin/env python3
"""
🍳 CloudCostChefs: OCI Forgotten Resource Detective (Python Edition)

Sniffs out forgotten cloud resources in your OCI tenancy—no manual sleuthing required. This script:
  • Scans every compartment (including root) like a bloodhound.
  • Flags:
      – Orphaned Block Volumes (no attachments, just sitting there collecting dust).
      – Unattached Public IPs (reserved but not feeding any VNIC).
      – Empty Network Security Groups (NSGs with zero VNICs).
      – Load Balancers with no backends (backend sets exist but are empty).
      – Old-gen Compute instances (matching a given shape regex).
      – Resources with absolutely NO tags (zero breadcrumbs for cost tracking).
      – Resources with sketchy names (test|temp|demo|old|backup|poc).
  • Outputs both a CSV and a CloudCostChefs-styled HTML report with cost estimates—candy for your CFO’s eyes.

Usage:
  python oci_forgotten_resources.py \
    --profile DEFAULT \
    --output-html forgotten_resources_report.html \
    --output-csv forgotten_resources_report.csv \
    --old-shape-pattern "VM\\.Standard1.*"
"""

import oci
import argparse
import csv
import re
import sys
import os
from datetime import datetime

# ------------------------------------------------------------
#  🍜 Helper: Gather all compartments (root + active children)
# ------------------------------------------------------------
def collect_all_compartments(identity_client, tenancy_id):
    """
    Returns a list of compartment OCIDs: [tenancy_id, <all active sub-compartments>].

    Think of this as collecting every ingredient in your kitchen before you start cooking.
    """
    compartments = []

    # List every ACTIVE compartment under the tenancy (recursive)
    all_response = oci.pagination.list_call_get_all_results(
        identity_client.list_compartments,
        compartment_id=tenancy_id,
        compartment_id_in_subtree=True,
        lifecycle_state="ACTIVE"
    )

    for cp in all_response.data:
        compartments.append(cp.id)

    # Don’t forget the root itself—it’s also fair game
    compartments.append(tenancy_id)
    return compartments

# ------------------------------------------------------------
#  🍳 Helper: Check for ZERO tags
# ------------------------------------------------------------
def has_no_tags(resource):
    """
    Returns True if both freeform_tags and defined_tags are empty or absent.

    In CloudCostChefs terms, this is like finding a dish with no seasoning—costs will be hard to track!
    """
    ff = getattr(resource, "freeform_tags", None)
    df = getattr(resource, "defined_tags", None)
    if (not ff or len(ff) == 0) and (not df or len(df) == 0):
        return True
    return False

# ------------------------------------------------------------
#  🔍 Scanner: Inspect a single compartment for forgotten resources
# ------------------------------------------------------------
def scan_compartment(
    comp_id,
    compute_client,
    blockstorage_client,
    network_client,
    lb_client,
    old_shape_pattern,
    suspicious_name_regex
):
    """
    For a given compartment, identify:
      • Orphaned Block Volumes
      • Unattached Public IPs
      • Empty NSGs
      • Load Balancers with no backends
      • Old-gen Compute instances (shape matches regex)
      • Resources with ZERO tags
      • Resources whose name matches suspicious patterns
    Returns a list of dicts—each dict is one “recipe for disaster” resource.
    """
    findings = []

    # 1) 🍞 Orphaned Block Volumes (no attachments → wasted storage cost)
    vols = oci.pagination.list_call_get_all_results(
        blockstorage_client.list_volumes,
        compartment_id=comp_id
    ).data

    for vol in vols:
        # Find any attachments for this volume
        attachments = compute_client.list_volume_attachments(
            compartment_id=comp_id,
            volume_id=vol.id
        ).data

        # If no attachments found → it’s orphaned (sad and wasted)
        if len(attachments) == 0:
            size_gb = vol.size_in_gbs or 0
            est_cost = round(size_gb * 0.025, 2)  # Rough estimate: $0.025 per GB/mo
            findings.append({
                "ResourceName": vol.display_name,
                "ResourceType": "BlockVolume",
                "CompartmentId": comp_id,
                "Issue": "Orphaned Block Volume",
                "RiskLevel": "High",
                "CostEstimate": f"${est_cost}/mo" if size_gb > 0 else "Unknown",
                "AdditionalInfo": f"Size: {size_gb} GB, AD: {vol.availability_domain}",
                "FreeformTags": vol.freeform_tags or {},
                "DefinedTags": vol.defined_tags or {},
            })

    # 2) 🏷️ Unattached Public IPs (Reserved but floating free)
    public_ips = oci.pagination.list_call_get_all_results(
        network_client.list_public_ips,
        compartment_id=comp_id,
        scope="REGION"
    ).data

    for pip in public_ips:
        # A “Reserved” public IP has an ip_address and lifetime=="RESERVED"
        if pip.lifetime == "RESERVED" and not pip.private_ip_id:
            # Cost estimate: ~$3.65/mo for a reserved IP in many regions
            est_cost = "$3.65/mo"
            findings.append({
                "ResourceName": pip.display_name or pip.ip_address,
                "ResourceType": "PublicIP",
                "CompartmentId": comp_id,
                "Issue": "Unattached Public IP",
                "RiskLevel": "Medium",
                "CostEstimate": est_cost,
                "AdditionalInfo": f"IP: {pip.ip_address}, Scope: {pip.scope}",
                "FreeformTags": pip.freeform_tags or {},
                "DefinedTags": pip.defined_tags or {},
            })

    # 3) 🔒 Empty Network Security Groups (NSGs with no VNICs → security config is pointless)
    nsgs = oci.pagination.list_call_get_all_results(
        network_client.list_network_security_groups,
        compartment_id=comp_id
    ).data

    for nsg in nsgs:
        attached_vnics = network_client.list_network_security_group_vnics(
            network_security_group_id=nsg.id
        ).data

        if len(attached_vnics) == 0:
            findings.append({
                "ResourceName": nsg.display_name,
                "ResourceType": "NetworkSecurityGroup",
                "CompartmentId": comp_id,
                "Issue": "Empty NSG",
                "RiskLevel": "Low",
                "CostEstimate": "Free",
                "AdditionalInfo": "No attached VNICs",
                "FreeformTags": nsg.freeform_tags or {},
                "DefinedTags": nsg.defined_tags or {},
            })

    # 4) ⚖️ Load Balancers with no backends (front-end but nowhere to serve traffic)
    lbs = oci.pagination.list_call_get_all_results(
        lb_client.list_load_balancers,
        compartment_id=comp_id
    ).data

    for lb in lbs:
        try:
            details = lb_client.get_load_balancer(load_balancer_id=lb.id).data
            backend_sets = details.backend_sets or {}
            empty = True

            # Loop each backend set; if any have backends, it’s not empty
            for bs in backend_sets.values():
                if bs.backends and len(bs.backends) > 0:
                    empty = False
                    break

            if empty:
                findings.append({
                    "ResourceName": lb.display_name,
                    "ResourceType": "LoadBalancer",
                    "CompartmentId": comp_id,
                    "Issue": "Empty Load Balancer",
                    "RiskLevel": "High",
                    "CostEstimate": "$18.25/mo",  # Rough monthly LB cost
                    "AdditionalInfo": f"Shape: {details.shape_name}, SubnetCount: {len(details.subnet_ids)}",
                    "FreeformTags": lb.freeform_tags or {},
                    "DefinedTags": lb.defined_tags or {},
                })
        except oci.exceptions.ServiceError:
            # If details fetch fails, just skip—no point in crashing the whole show
            continue

    # 5) 👴 Old-Generation Instances (shape matches regex → likely inefficient)
    instances = oci.pagination.list_call_get_all_results(
        compute_client.list_instances,
        compartment_id=comp_id
    ).data

    for inst in instances:
        shape = inst.shape or ""
        if re.match(old_shape_pattern, shape):
            findings.append({
                "ResourceName": inst.display_name,
                "ResourceType": "ComputeInstance",
                "CompartmentId": comp_id,
                "Issue": f"Old-gen Shape ({shape})",
                "RiskLevel": "Medium",
                "CostEstimate": "Varies",
                "AdditionalInfo": f"Shape: {shape}, Lifecycle: {inst.lifecycle_state}",
                "FreeformTags": inst.freeform_tags or {},
                "DefinedTags": inst.defined_tags or {},
            })

    # 6) 🏷️ Resources with ZERO TAGS (no breadcrumbs for cost tracking)
    #    We'll check the same resource collections above
    resource_collections = [
        ("ComputeInstance", instances),
        ("BlockVolume", vols),
        ("PublicIP", public_ips),
        ("NetworkSecurityGroup", nsgs),
        ("LoadBalancer", lbs),
    ]
    for rtype, coll in resource_collections:
        for res in coll:
            if has_no_tags(res):
                findings.append({
                    "ResourceName": res.display_name if hasattr(res, "display_name") else getattr(res, "ip_address", "<unknown>"),
                    "ResourceType": rtype,
                    "CompartmentId": comp_id,
                    "Issue": "No Tags",
                    "RiskLevel": "High",
                    "CostEstimate": "Varies",
                    "AdditionalInfo": "",
                    "FreeformTags": res.freeform_tags or {},
                    "DefinedTags": res.defined_tags or {},
                })

    # 7) 🚩 Suspicious Name Patterns (test/temp/demo/old/backup/poc)
    for rtype, coll in resource_collections:
        for res in coll:
            name = res.display_name if hasattr(res, "display_name") else str(getattr(res, "ip_address", ""))
            if re.search(suspicious_name_regex, name, re.IGNORECASE):
                findings.append({
                    "ResourceName": name,
                    "ResourceType": rtype,
                    "CompartmentId": comp_id,
                    "Issue": "Suspicious Name Pattern",
                    "RiskLevel": "High",
                    "CostEstimate": "Varies",
                    "AdditionalInfo": "",
                    "FreeformTags": res.freeform_tags or {},
                    "DefinedTags": res.defined_tags or {},
                })

    return findings

# ------------------------------------------------------------
#  🔥 Main Entrypoint: Orchestrate the Detective Work
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="🍳 OCI Forgotten Resource Detective (Python edition)"
    )
    parser.add_argument(
        "--profile",
        required=False,
        default="DEFAULT",
        help="OCI CLI profile name (default: DEFAULT) from ~/.oci/config"
    )
    parser.add_argument(
        "--old-shape-pattern",
        required=False,
        default=r"VM\.Standard1.*",
        help="Regex to flag old-gen compute shapes (default: VM\\.Standard1.*)"
    )
    parser.add_argument(
        "--output-csv",
        required=False,
        default="forgotten_resources_report.csv",
        help="Path to write CSV report (default: forgotten_resources_report.csv)"
    )
    parser.add_argument(
        "--output-html",
        required=False,
        default="forgotten_resources_report.html",
        help="Path to write HTML report (default: forgotten_resources_report.html)"
    )
    parser.add_argument(
        "--suspicious-name-regex",
        required=False,
        default=r"\b(test|temp|demo|old|backup|poc)\b",
        help="Regex for sketchy resource names (default: \\b(test|temp|demo|old|backup|poc)\\b)"
    )

    args = parser.parse_args()

    # 🍴 Load OCI config and clients
    try:
        config = oci.config.from_file(profile_name=args.profile)
    except Exception as e:
        print(f"❌ Whoa! Failed to load OCI config for profile '{args.profile}': {e}")
        sys.exit(1)

    tenancy_id = config.get("tenancy")
    if not tenancy_id:
        print("❌ Couldn’t find 'tenancy' in OCI config. Exiting.")
        sys.exit(1)

    identity_client      = oci.identity.IdentityClient(config)
    compute_client       = oci.core.ComputeClient(config)
    blockstorage_client  = oci.core.BlockstorageClient(config)
    network_client       = oci.core.VirtualNetworkClient(config)
    lb_client            = oci.load_balancer.LoadBalancerClient(config)

    print(f"🔍 Fetching all active compartments under tenancy {tenancy_id} …")
    compartments = collect_all_compartments(identity_client, tenancy_id)
    print(f"   Found {len(compartments)} compartments (including root).")
    print()

    all_findings = []

    # 🍽️ Scan each compartment
    for comp_id in compartments:
        print(f"⏳ Scanning compartment {comp_id} …")
        compartment_findings = scan_compartment(
            comp_id,
            compute_client,
            blockstorage_client,
            network_client,
            lb_client,
            old_shape_pattern=args.old_shape_pattern,
            suspicious_name_regex=args.suspicious_name_regex
        )
        all_findings.extend(compartment_findings)

    # 📋 Report summary
    if not all_findings:
        print("✅ All clean! No forgotten clouds here.")
    else:
        print(f"⚠️  Found {len(all_findings)} forgotten/suspicious resources in total.")

        # --------------- Generate CSV Report ----------------
        csv_path = args.output_csv
        with open(csv_path, mode="w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "ResourceName", "ResourceType", "CompartmentId",
                "Issue", "RiskLevel", "CostEstimate",
                "AdditionalInfo", "FreeformTags", "DefinedTags"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for item in all_findings:
                # Convert tags dicts to string for CSV readability
                item["FreeformTags"] = "{}" if not item["FreeformTags"] else str(item["FreeformTags"])
                item["DefinedTags"] = "{}" if not item["DefinedTags"] else str(item["DefinedTags"])
                writer.writerow(item)

        print(f"🗒️  CSV report saved to: {csv_path}")

        # --------------- Generate CloudCostChefs-Styled HTML ----------------
        html_path = args.output_html
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OCI Forgotten Resource Detective Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f9f9f9; margin: 20px; }}
        h1 {{ color: #2c3e50; font-size: 28px; }}
        p {{ font-size: 14px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 13px; }}
        th {{ background: #34495e; color: white; }}
        tr:nth-child(even) {{ background: #f2f2f2; }}
        .high {{ background: #fdecea; }}   /* Light red for high risk */
        .medium {{ background: #fff4e5; }} /* Light orange for medium */
        .low {{ background: #e8f5e9; }}    /* Light green for low */
        .footer {{ margin-top: 30px; font-size: 12px; color: #555; }}
    </style>
</head>
<body>
    <h1>🕵️ OCI Forgotten Resource Detective</h1>
    <p><strong>Generated:</strong> {now}</p>
    <p><strong>Total Issues Found:</strong> {len(all_findings)}</p>

    <table>
        <tr>
            <th>Risk</th>
            <th>Resource Name</th>
            <th>Type</th>
            <th>Compartment</th>
            <th>Issue</th>
            <th>Cost Estimate</th>
            <th>Additional Info</th>
            <th>Tags</th>
        </tr>"""

        for item in all_findings:
            risk = item["RiskLevel"].lower()
            tags_str = ""
            if item["FreeformTags"] and item["FreeformTags"] != "{}":
                tags_str += f"FF: {item['FreeformTags']}<br/>"
            if item["DefinedTags"] and item["DefinedTags"] != "{}":
                tags_str += f"DT: {item['DefinedTags']}"

            html_content += f"""
        <tr class="{risk}">
            <td>{item['RiskLevel']}</td>
            <td>{item['ResourceName']}</td>
            <td>{item['ResourceType']}</td>
            <td>{item['CompartmentId']}</td>
            <td>{item['Issue']}</td>
            <td>{item['CostEstimate']}</td>
            <td>{item['AdditionalInfo']}</td>
            <td>{tags_str}</td>
        </tr>"""

        html_content += """
    </table>

    <div class="footer">
        <p>🔍 Report generated by OCI Forgotten Resource Detective (Python, CloudCostChefs edition)</p>
        <p>⚠️ Review each before you delete! Verify dependencies and confirm with app owners.</p>
    </div>
</body>
</html>
"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"🖼️  HTML report saved to: {html_path}")

if __name__ == "__main__":
    main()
