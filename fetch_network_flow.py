import os
import sys
import csv
import boto3
import botocore
from typing import List, Dict, Any, Set
import json
import configparser

# --------------------------------------------------------------------------- #
# 인증 및 계정 로딩 로직 (bluewalnut_fetch_ec2_info.py 독립 복사본)

TMP_JSON = os.path.join(os.path.dirname(__file__), "bluewalnut.json")
AWS_CREDENTIALS_FILE = os.path.expanduser("~/.aws/credentials")
SESSION_NAME = "AssumeRoleSession"

# 커버할 리전 목록
REGIONS = [
    "ap-northeast-2",
    "ap-northeast-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "us-east-1",
    "us-west-1",
    "us-west-2",
    "eu-central-1",
    "eu-west-1",
    "ap-south-1",
]

# 계정 정보 로드 (bluewalnut.json)
def load_accounts() -> List[Dict[str, Any]]:
    with open(TMP_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

# STS AssumeRole 를 통해 ~/.aws/credentials 에 임시 자격증명 저장
def refresh_credentials(account: Dict[str, Any]) -> bool:
    role_arn = f"arn:aws:iam::{account['account_id']}:role/{account['role_name']}"
    profile_name = account["name"]

    try:
        # 이미 해당 프로파일이 유효한지 체크
        session = boto3.Session(profile_name=profile_name)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        current_arn = identity["Arn"]
        if current_arn.startswith(f"arn:aws:sts::{account['account_id']}:assumed-role/{account['role_name']}"):
            print(f"✅ 이미 {profile_name} 역할 사용 중, 갱신 생략")
            return True
    except Exception:
        # 프로파일이 없거나 만료된 경우 계속 진행
        pass

    # AssumeRole 수행
    try:
        sts = boto3.client("sts")
        assumed_role = sts.assume_role(RoleArn=role_arn, RoleSessionName=SESSION_NAME)

        config = configparser.ConfigParser()
        if os.path.exists(AWS_CREDENTIALS_FILE):
            config.read(AWS_CREDENTIALS_FILE)

        if profile_name not in config:
            config.add_section(profile_name)

        config[profile_name]["aws_access_key_id"] = assumed_role["Credentials"]["AccessKeyId"]
        config[profile_name]["aws_secret_access_key"] = assumed_role["Credentials"]["SecretAccessKey"]
        config[profile_name]["aws_session_token"] = assumed_role["Credentials"]["SessionToken"]
        config[profile_name]["region"] = "ap-northeast-2"

        with open(AWS_CREDENTIALS_FILE, "w") as f:
            config.write(f)
        print(f"✅ 자격 증명 갱신 완료: {profile_name}")
        return True
    except botocore.exceptions.ClientError as e:
        print(f"🚨 STS AssumeRole 실패: {str(e)}")
        return False
    except Exception as e:
        print(f"🚨 예외 발생: {str(e)}")
        return False

def _get_tag_name(tags: List[Dict[str, Any]]) -> str:
    if not tags:
        return ""
    for t in tags:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


# ------------------------------ VPC & SUBNET ------------------------------ #

def collect_vpc_and_subnet_rows(ec2, account: str, region: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        # fetch all VPCs with paginator
        paginator = ec2.get_paginator('describe_vpcs')
        for page in paginator.paginate():
            for vpc in page.get('Vpcs', []):
                vpc_id = vpc.get("VpcId")
                name = _get_tag_name(vpc.get("Tags", []))
                # IPv4 CIDRs
                for assoc in vpc.get("CidrBlockAssociationSet", []):
                    rows.append(
                    {
                        "Account": account,
                        "Region": region,
                        "ResourceType": "VPC",
                        "ParentId": "",
                        "ResourceId": vpc_id,
                        "Name": name,
                        "IpCidr": assoc.get("CidrBlock"),
                        "Description": "VPC IPv4 CIDR",
                    }
                )
            # IPv6 CIDRs
                for assoc in vpc.get("Ipv6CidrBlockAssociationSet", []):
                    rows.append(
                    {
                        "Account": account,
                        "Region": region,
                        "ResourceType": "VPC",
                        "ParentId": "",
                        "ResourceId": vpc_id,
                        "Name": name,
                        "IpCidr": assoc.get("Ipv6CidrBlock"),
                        "Description": "VPC IPv6 CIDR",
                    }
                )
        # SUBNETS
        # fetch all Subnets with paginator
        paginator = ec2.get_paginator('describe_subnets')
        for page in paginator.paginate():
            for subnet in page.get('Subnets', []):
                subnet_id = subnet.get("SubnetId")
                name = _get_tag_name(subnet.get("Tags", []))
                rows.append(
                {
                    "Account": account,
                    "Region": region,
                    "ResourceType": "Subnet",
                    "ParentId": subnet.get("VpcId"),
                    "ResourceId": subnet_id,
                    "Name": name,
                    "IpCidr": subnet.get("CidrBlock"),
                    "Description": "Subnet IPv4 CIDR",
                }
            )
            if subnet.get("Ipv6CidrBlock"):
                rows.append(
                    {
                        "Account": account,
                        "Region": region,
                        "ResourceType": "Subnet",
                        "ParentId": subnet.get("VpcId"),
                        "ResourceId": subnet_id,
                        "Name": name,
                        "IpCidr": subnet.get("Ipv6CidrBlock"),
                        "Description": "Subnet IPv6 CIDR",
                    }
                )
    except botocore.exceptions.ClientError as e:
        print(f"[ERROR] {account} {region} VPC/Subnet 조회 실패: {e}")
    return rows


# ------------------------------ VPN ------------------------------ #

def collect_vpn_rows(ec2, account: str, region: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        # fetch all VPN connections
        vpn_conns = ec2.describe_vpn_connections()['VpnConnections']
        # customer gateway id 모아서 한 번에 조회
        cgw_ids: Set[str] = {vc.get('CustomerGatewayId') for vc in vpn_conns if vc.get('CustomerGatewayId')}
        cgw_ip_map: Dict[str, str] = {}
        if cgw_ids:
            cwgs = ec2.describe_customer_gateways(CustomerGatewayIds=list(cgw_ids)).get('CustomerGateways', [])
            for cg in cwgs:
                cgw_ip_map[cg['CustomerGatewayId']] = cg.get('IpAddress', '')
        for vc in vpn_conns:
            vpn_id = vc["VpnConnectionId"]
            name = _get_tag_name(vc.get("Tags", []))

            parent_gw = vc.get("VpnGatewayId") or vc.get("TransitGatewayId", "")
            # VPN 연결 자체 레코드 (Static vs Dynamic)
            rows.append(
                {
                    "Account": account,
                    "Region": region,
                    "ResourceType": "VPN",
                    "ParentId": parent_gw,
                    "ResourceId": vpn_id,
                    "Name": name,
                    "IpCidr": "",
                    "Description": "Static" if vc.get("Options", {}).get("StaticRoutesOnly") else "Dynamic",
                    "Edge": "",
                    "TargetType": "",
                }
            )
            # VGW ↔ VPN 링크 레코드
            if parent_gw:
                rows.append(
                    {
                        "Account": account,
                        "Region": region,
                        "ResourceType": "VGW_VPN_LINK",
                        "ParentId": parent_gw,
                        "ResourceId": vpn_id,
                        "Name": "",
                        "IpCidr": "",
                        "Description": "VGW-VPN attachment",
                        "Edge": "ATTACHED_TO",
                        "TargetType": "VPN",
                    }
                )

            cgw_id = vc.get("CustomerGatewayId", "")
            # 외부 Customer Gateway IP
            if cgw_id and cgw_ip_map.get(cgw_id):
                rows.append(
                    {
                        "Account": account,
                        "Region": region,
                        "ResourceType": "VPN_CGW",
                        "ParentId": vpn_id,
                        "ResourceId": cgw_id,
                        "Name": name,
                        "IpCidr": cgw_ip_map[cgw_id],
                        "Description": "CustomerGateway IP",
                        "Edge": "",
                        "TargetType": "",
                    }
                )
            # 정적 라우트
            for rt in vc.get("Routes", []):
                rows.append(
                    {
                        "Account": account,
                        "Region": region,
                        "ResourceType": "VPN_ROUTE",
                        "ParentId": vpn_id,
                        "ResourceId": vpn_id,
                        "Name": name,
                        "IpCidr": rt.get("DestinationCidrBlock"),
                        "Description": f"VPN static route ({rt.get('State')})",
                        "Edge": "",
                        "TargetType": "",
                    }
                )
    except botocore.exceptions.ClientError as e:
        if "InvalidVpnConnectionID.NotFound" in str(e):
            # region에 vpn이 없을 수 있음
            pass
        else:
            print(f"[ERROR] {account} {region} VPN 조회 실패: {e}")
    return rows


# ------------------------------ TRANSIT GATEWAY ------------------------------ #

def collect_transit_gateway_rows(ec2, account: str, region: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        # fetch all Transit Gateways with paginator
        paginator = ec2.get_paginator('describe_transit_gateways')
        for page in paginator.paginate():
            for tgw in page.get('TransitGateways', []):
                tgw_id = tgw.get("TransitGatewayId")
                name = _get_tag_name(tgw.get("Tags", []))
                cidrs = tgw.get("Options", {}).get("TransitGatewayCidrBlocks", [])
                for cidr in cidrs:
                    rows.append(
                        {
                            "Account": account,
                            "Region": region,
                            "ResourceType": "TGW",
                            "ParentId": "",
                            "ResourceId": tgw_id,
                            "Name": name,
                            "IpCidr": cidr,
                            "Description": "Transit Gateway CIDR",
                            "Edge": "",
                            "TargetType": "",
                        }
                    )
    except botocore.exceptions.ClientError as e:
        if "InvalidTransitGatewayID.NotFound" in str(e):
            pass
        else:
            print(f"[ERROR] {account} {region} TGW 조회 실패: {e}")
    return rows


# ------------------------------ SECURITY GROUP ------------------------------ #

def collect_security_group_rows(ec2, account: str, region: str) -> List[Dict[str, Any]]:
    """보안 그룹 전체(인스턴스에 붙지 않은 SG 포함)를 조회해 IP/CIDR 정보를 수집"""
    rows: List[Dict[str, Any]] = []
    try:
        # 모든 SG 조회 (필터 없이)
        # fetch all Security Groups with paginator
        paginator = ec2.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            for sg in page.get('SecurityGroups', []):
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "")
                # 인바운드
                for perm in sg.get("IpPermissions", []):
                    for ip in perm.get("IpRanges", []):  # IPv4
                        rows.append(
                            {
                                "Account": account,
                                "Region": region,
                                "ResourceType": "SG_INGRESS",
                                "ParentId": sg_id,
                                "ResourceId": sg_id,
                                "Name": sg_name,
                                "IpCidr": ip.get("CidrIp"),
                                "Description": ip.get("Description", ""),
                                "Edge": "",
                                "TargetType": "",
                            }
                        )
                    for ip in perm.get("Ipv6Ranges", []):  # IPv6
                        rows.append(
                            {
                                "Account": account,
                                "Region": region,
                                "ResourceType": "SG_INGRESS",
                                "ParentId": sg_id,
                                "ResourceId": sg_id,
                                "Name": sg_name,
                                "IpCidr": ip.get("CidrIpv6"),
                                "Description": ip.get("Description", ""),
                                "Edge": "",
                                "TargetType": "",
                            }
                        )
                # 아웃바운드
                for perm in sg.get("IpPermissionsEgress", []):
                    for ip in perm.get("IpRanges", []):
                        rows.append(
                            {
                                "Account": account,
                                "Region": region,
                                "ResourceType": "SG_EGRESS",
                                "ParentId": sg_id,
                                "ResourceId": sg_id,
                                "Name": sg_name,
                                "IpCidr": ip.get("CidrIp"),
                                "Description": ip.get("Description", ""),
                                "Edge": "",
                                "TargetType": "",
                            }
                        )
                    for ip in perm.get("Ipv6Ranges", []):
                        rows.append(
                            {
                                "Account": account,
                                "Region": region,
                                "ResourceType": "SG_EGRESS",
                                "ParentId": sg_id,
                                "ResourceId": sg_id,
                                "Name": sg_name,
                                "IpCidr": ip.get("CidrIpv6"),
                                "Description": ip.get("Description", ""),
                                "Edge": "",
                                "TargetType": "",
                            }
                        )
    except botocore.exceptions.ClientError as e:
        print(f"[ERROR] {account} {region} SG 조회 실패: {e}")
    return rows


# ------------------------------ EC2 INSTANCES ------------------------------ #

def collect_instance_rows(ec2, account: str, region: str) -> List[Dict[str, Any]]:
    """인스턴스 정보 및 인스턴스-SG 매핑 수집"""
    rows: List[Dict[str, Any]] = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for res in page.get("Reservations", []):
            for inst in res.get("Instances", []):
                inst_id = inst["InstanceId"]
                name = _get_tag_name(inst.get("Tags", []))
                subnet_id = inst.get("SubnetId", "")
                vpc_id = inst.get("VpcId", "")
                # 인스턴스 자체 노드
                rows.append(
                    {
                        "Account": account,
                        "Region": region,
                        "ResourceType": "Instance",
                        "ParentId": subnet_id or vpc_id,
                        "ResourceId": inst_id,
                        "Name": name,
                        "IpCidr": inst.get("PrivateIpAddress", ""),
                        "Description": "EC2 Instance",
                        "Edge": "",
                        "TargetType": "",
                    }
                )
                # 인스턴스-SG 연결
                for sg in inst.get("SecurityGroups", []):
                    rows.append(
                        {
                            "Account": account,
                            "Region": region,
                            "ResourceType": "InstanceSG",
                            "ParentId": inst_id,
                            "ResourceId": sg["GroupId"],
                            "Name": sg.get("GroupName", ""),
                            "IpCidr": "",
                            "Description": "Instance attached SG",
                            "Edge": "ATTACHED_TO",
                            "TargetType": "SG",
                        }
                    )
    return rows


# ------------------------------ ROUTE TABLES ------------------------------ #

def _route_target_and_desc(route: Dict[str, Any]) -> (str, str):
    for key in (
        "GatewayId",
        "NatGatewayId",
        "TransitGatewayId",
        "VpcPeeringConnectionId",
        "InstanceId",
        "NetworkInterfaceId",
        "LocalGatewayId",
        "CarrierGatewayId",
        "EgressOnlyInternetGatewayId",
    ):
        if route.get(key):
            return route[key], key
    # local routes have no target
    return "local", "local"


def collect_route_table_rows(ec2, account: str, region: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        # fetch all Route Tables with paginator
        paginator = ec2.get_paginator('describe_route_tables')
        for page in paginator.paginate():
            for rtb in page.get('RouteTables', []):
                rtb_id = rtb["RouteTableId"]
                vpc_id = rtb["VpcId"]
                # 노드 자체
                rows.append(
                    {
                        "Account": account,
                        "Region": region,
                        "ResourceType": "RouteTable",
                        "ParentId": vpc_id,
                        "ResourceId": rtb_id,
                        "Name": "",
                        "IpCidr": "",
                        "Description": "",
                        "Edge": "",
                        "TargetType": "",
                    }
                )
                # Associations
                for assoc in rtb.get("Associations", []):
                    subnet_id = assoc.get("SubnetId", "main" if assoc.get("Main") else "")
                    if subnet_id:
                        rows.append(
                            {
                                "Account": account,
                                "Region": region,
                                "ResourceType": "RT_ASSOC",
                                "ParentId": rtb_id,
                                "ResourceId": subnet_id,
                                "Name": "",
                                "IpCidr": "",
                                "Description": "Main" if assoc.get("Main") else "SubnetAssociation",
                                "Edge": "ASSOCIATED_WITH",
                                "TargetType": "Subnet",
                            }
                        )
                # Routes
                for route in rtb.get("Routes", []):
                    dest_cidr = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
                    target, target_type = _route_target_and_desc(route)
                    if dest_cidr:
                        rows.append(
                            {
                                "Account": account,
                                "Region": region,
                                "ResourceType": "RT_ROUTE",
                                "ParentId": rtb_id,
                                "ResourceId": target,
                                "Name": target_type,
                                "IpCidr": dest_cidr,
                                "Description": f"RT route ({route.get('Origin','')}) -> {target_type}",
                                "Edge": "ROUTE_TARGET",
                                "TargetType": target_type,
                            }
                        )
    except botocore.exceptions.ClientError as e:
        print(f"[ERROR] {account} {region} RT 조회 실패: {e}")
    return rows


# ------------------------------ VGW ------------------------------ #

def collect_vgw_rows(ec2, account: str, region: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        # fetch all VGWs
        vgws = ec2.describe_vpn_gateways()['VpnGateways']
        for vgw in vgws:
            vgw_id = vgw["VpnGatewayId"]
            for attach in vgw.get("VpcAttachments", []):
                rows.append(
                    {
                        "Account": account,
                        "Region": region,
                        "ResourceType": "VGW",
                        "ParentId": attach.get("VpcId", ""),
                        "ResourceId": vgw_id,
                        "Name": "",
                        "IpCidr": "",
                        "Description": f"State:{attach.get('State')}",
                        "Edge": "",
                        "TargetType": "",
                    }
                )
    except botocore.exceptions.ClientError:
        pass
    return rows


# ------------------------------ TGW ATTACHMENTS ------------------------------ #

def collect_tgw_attachment_rows(ec2, account: str, region: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        # fetch all TGW Attachments with paginator
        paginator = ec2.get_paginator('describe_transit_gateway_attachments')
        for page in paginator.paginate():
            for att in page.get('TransitGatewayAttachments', []):
                rows.append(
                    {
                        "Account": account,
                        "Region": region,
                        "ResourceType": "TGW_ATTACH",
                        "ParentId": att.get("TransitGatewayId", ""),
                        "ResourceId": att.get("ResourceId", ""),
                        "Name": att.get("ResourceType", ""),
                        "IpCidr": "",
                        "Description": f"State:{att.get('State')}",
                        "Edge": "ATTACHED_TO",
                        "TargetType": att.get("ResourceType", ""),
                    }
                )
    except botocore.exceptions.ClientError:
        pass
    return rows


# ------------------------------ MAIN ------------------------------ #

def main():
    accounts = load_accounts()
    for account in accounts:
        print(f"\n==== {account['name']} ===")
        if not refresh_credentials(account):
            print(f"❌ assume role 실패: {account['name']}")
            continue
        profile_name = account["name"]
        account_rows: List[Dict[str, Any]] = []
        for region in REGIONS:
            try:
                session = boto3.Session(profile_name=profile_name)
                ec2 = session.client("ec2", region_name=region)
                rows_region: List[Dict[str, Any]] = []
                rows_region.extend(collect_instance_rows(ec2, profile_name, region))
                rows_region.extend(collect_vpc_and_subnet_rows(ec2, profile_name, region))
                rows_region.extend(collect_vpn_rows(ec2, profile_name, region))
                rows_region.extend(collect_vgw_rows(ec2, profile_name, region))
                rows_region.extend(collect_transit_gateway_rows(ec2, profile_name, region))
                rows_region.extend(collect_tgw_attachment_rows(ec2, profile_name, region))
                rows_region.extend(collect_security_group_rows(ec2, profile_name, region))
                rows_region.extend(collect_route_table_rows(ec2, profile_name, region))
                account_rows.extend(rows_region)
                print(f"[DEBUG] {profile_name} {region} rows: {len(rows_region)}")
            except Exception as e:
                print(f"[ERROR] {profile_name} {region} 예외: {e}")



if __name__ == "__main__":
    main()