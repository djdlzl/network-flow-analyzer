from __future__ import annotations

import ipaddress
import os
import json
from typing import List, Dict, Any
from datetime import datetime, timezone
import hashlib
import boto3

import fetch_network_flow as nf

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from qdrant_client import QdrantClient, models as qdrant
from qdrant_client.http.exceptions import UnexpectedResponse
try:
    from langchain_aws.chat_models import ChatBedrock  # >=0.1.16
except ImportError:  # fallback for older versions
    from langchain_community.chat_models.bedrock import BedrockChat as ChatBedrock
from langchain.prompts import ChatPromptTemplate

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
ACCOUNTS_JSON = os.path.join(BASE_DIR, "governance_docs", "account.json")
FRONTEND_DIR = os.path.join(BASE_DIR, "front")

QDRANT_URL = os.environ.get("QDRANT_URL", "http://localhost:6333")
COLLECTION = os.environ.get("QDRANT_COLLECTION", "aws_network")

VECTOR_SIZE = 1

client = QdrantClient(url=QDRANT_URL)
chat_model: ChatBedrock | None = None

def _get_chat_model():
    global chat_model
    if chat_model is None:
        chat_model = ChatBedrock(model_id="amazon.nova-pro-v1:0", region_name="us-east-1")
    return chat_model

PROMPT_TMPL = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "당신은 AWS 네트워크 아키텍트입니다. 제공된 네트워크 토폴로지 정보를 바탕으로 사용자 질문에 대해 통신 가능 여부를 설명하십시오. 출발지와 목적지를 정확히 파악하고 실제 존재하는 리소스만 언급하세요.",
        ),
        (
            "user",
            "네트워크 토폴로지 일부:\n{context}\n\n질문:\n{question}\n\n답변 시 지침:\n1. 먼저 통신 가능 여부에 대한 설명을 2-3문장으로 제시하세요. 퍼블릭/프라이빗 통신인지 명시하고 이유를 설명합니다.\n\n2. 그 다음에 '### 네트워크 흐름' 제목으로 구분하여 네트워크 경로를 보여주세요.\n\n3. 네트워크 경로는 화살표(->)로 연결된 단계별 실제 리소스들을 보여주되:\n   - 예시나 가상 리소스 ID는 절대 사용하지 말고, 데이터에 실제 존재하는 리소스만 포함하세요\n   - 데이터에서 확인할 수 없는 인스턴스나 서브넷 등은 언급하지 마세요\n   - 각 단계는 반드시 실제 존재하는 리소스 ID와 해당되는 IP 대역을 포함해야 합니다\n   - 여러 경로가 있으면 경로마다 '#### 경로 N:' 형식으로 구분하세요\n   - 각 리소스 단계는 개별 라인에 표시하세요 (마크다운 줄바꿈 활용)\n\n4. 경로 정보는 다음과 같은 형식으로 작성하세요:\n   RTB(rtb-실제ID) 10.0.0.0/16 -> VGW(vgw-실제ID)\n   -> VPN(vpn-실제ID) -> 목적지CIDR\n\n5. 통신이 불가능한 경우, 어느 단계에서 막히는지 자세히 설명하세요.\n\n6. 모든 답변은 마크다운 형식으로 작성하고, 한국어로 간결하게 작성하세요. \n7. RT_ROUTE의 Gateway(VGW)와 VGW_VPN_LINK 단계의 VGW가 일치하는 VPN만 경로에 포함하고, 일치하지 않는 VPN은 무시하세요.\n8. 네트워크 출발지와 목적지가 질문에 명확하지 않은 경우, 네트워크의 출발지로 subnet을 확인하세요.",
        ),
    ]
)

app = FastAPI(title="Network Flow Analysis API")


class PromptIn(BaseModel):
    account_name: str
    prompt: str
    refresh: bool | None = False
    regions: List[str] | None = None


# --------------------------------------------------------------------------- #
# Helper
# --------------------------------------------------------------------------- #

def parse_networks(text: str):
    import re

    pattern_cidr = r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}"
    # 와일드카드(10.81.x.x, 10.*.*.*, 10.81.0.* 등) 매칭: 각 옥텟 앞에 반드시 '.'가 존재하도록 수정
    pattern_wild = r"\d{1,3}(?:\.(?:\d{1,3}|\*|x)){3}"
    # 두 옥텟(예: 10.81)만 명시된 경우를 /16 대역으로 해석
    pattern_prefix16 = r"\b\d{1,3}\.\d{1,3}\b"

    networks = []
    for c in re.findall(pattern_cidr, text):
        try:
            networks.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    for w in re.findall(pattern_wild, text):
        if "*" in w or "x" in w:
            parts = w.split(".")
            star_cnt = sum(1 for p in parts if p == "*" or p == "x")
            mask = 32 - star_cnt * 8
            ip_base = ".".join(["0" if p == "*" or p == "x" else p for p in parts])
            try:
                networks.append(ipaddress.ip_network(f"{ip_base}/{mask}", strict=False))
            except ValueError:
                pass
    # 두 옥텟 접두사가 있을 경우 (/16)
    for p in re.findall(pattern_prefix16, text):
        try:
            networks.append(ipaddress.ip_network(f"{p}.0.0/16", strict=False))
        except ValueError:
            pass
    return networks


# --------------------------------------------------------------------------- #
# Qdrant search by cidr overlap
# --------------------------------------------------------------------------- #

def range_filter_expr(start: int, end: int):
    return qdrant.Filter(must=[
        qdrant.FieldCondition(key="cidr_start", range=qdrant.Range(lte=end)),
        qdrant.FieldCondition(key="cidr_end", range=qdrant.Range(gte=start)),
    ])


def fetch_context_rows(account: str, networks, regions: List[str] | None = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for net in networks:
        s, e = int(net.network_address), int(net.broadcast_address)
        try:
            must_conds = [
                range_filter_expr(s, e),
                qdrant.FieldCondition(key="Account", match=qdrant.MatchValue(value=account)),
            ]
            if regions:
                must_conds.append(qdrant.FieldCondition(key="Region", match=qdrant.MatchAny(any=regions)))
            res = client.search(
                collection_name=COLLECTION,
                query_vector=[0.0],
                limit=200,
                query_filter=qdrant.Filter(must=must_conds),
                with_payload=True,
            )
        except UnexpectedResponse as ue:
            # Qdrant 컬렉션이 없으면 사용자에게 안내
            if "doesn't exist" in str(ue):
                raise HTTPException(status_code=404, detail="Qdrant에 컬렉션이 없습니다. 먼저 ingestion 스크립트를 실행하세요.")
            raise

        rows.extend(p.payload for p in res)
    # dedup by id + cidr
    seen = set()
    uniq = []
    for r in rows:
        key = (r.get("ResourceId"), r.get("IpCidr"))
        if key not in seen:
            uniq.append(r)
            seen.add(key)
    # ---- 2단계: 연관 리소스 확장 ---- #
    id_set = {r["ResourceId"] for r in uniq if r.get("ResourceId")}
    id_set.update({r.get("ParentId") for r in uniq if r.get("ParentId")})
    id_set.discard(None)

    if id_set:
        id_list = list(id_set)
        if len(id_list) > 256:
            id_list = id_list[:256]
        try:
            extra, _ = client.scroll(
                collection_name=COLLECTION,
                scroll_filter=qdrant.Filter(
                    must=[
                        qdrant.FieldCondition(key="Account", match=qdrant.MatchValue(value=account))
                    ] + ([qdrant.FieldCondition(key="Region", match=qdrant.MatchAny(any=regions))] if regions else []),
                    should=[
                        qdrant.FieldCondition(key="ResourceId", match=qdrant.MatchAny(any=id_list)),
                        qdrant.FieldCondition(key="ParentId", match=qdrant.MatchAny(any=id_list)),
                    ],
                ),
                with_payload=True,
                limit=2000,
            )
            for pt in extra:
                p = pt.payload
                key = (p.get("ResourceId"), p.get("IpCidr"))
                if key not in seen:
                    uniq.append(p)
                    seen.add(key)
        except Exception:
            pass

    return uniq[:1000]


# --------------------------------------------------------------------------- #
# LLM
# --------------------------------------------------------------------------- #

def row_to_line(r: Dict[str, Any]) -> str:
    # convert a row to a relationship line for context with detailed resource info
    rt = r.get("ResourceType")
    
    # 라우트 테이블 경로 (라우팅 정보가 가장 중요)
    if rt == "RT_ROUTE":
        target_type = r.get('TargetType', '')
        resource_id = r.get('ResourceId', '')
        parent_id = r.get('ParentId', '')
        cidr = r.get('IpCidr', '')
        return f"ROUTE_TABLE {parent_id} ROUTES {cidr} -> {target_type} {resource_id}"
    
    # VGW와 VPN 연결 링크
    # RTB <-> Subnet association
    elif rt == "RT_ASSOC":
        rtb_id = r.get('ParentId', '')
        subnet_id = r.get('ResourceId', '')
        return f"ROUTE_TABLE {rtb_id} ASSOCIATED_WITH SUBNET {subnet_id}"

    # VPN static/propagated route
    elif rt == "VPN_ROUTE":
        vpn_id = r.get('ParentId', '') or r.get('ResourceId', '')
        cidr = r.get('IpCidr', '')
        return f"VPN {vpn_id} ROUTES {cidr}"

    elif rt == "VGW_VPN_LINK":
        parent_id = r.get('ParentId', '')
        resource_id = r.get('ResourceId', '')
        return f"VGW {parent_id} CONNECTS_TO VPN {resource_id}"
    
    # 인스턴스 정보 추가
    elif rt == "INSTANCE":
        instance_id = r.get('ResourceId', '')
        private_ip = r.get('PrivateIp', '')
        subnet_id = r.get('ParentId', '')
        return f"INSTANCE {instance_id} IN {subnet_id} HAS_IP {private_ip}"
    
    # 서브넷 정보 추가
    elif rt == "SUBNET":
        subnet_id = r.get('ResourceId', '')
        cidr = r.get('IpCidr', '')
        vpc_id = r.get('ParentId', '')
        return f"SUBNET {subnet_id} IN {vpc_id} HAS_CIDR {cidr}"
    
    # VPC 정보 추가
    elif rt == "VPC":
        vpc_id = r.get('ResourceId', '')
        cidr = r.get('IpCidr', '')
        return f"VPC {vpc_id} HAS_CIDR {cidr}"
    
    # VPN 연결 정보 추가
    elif rt == "VPN":
        vpn_id = r.get('ResourceId', '')
        remote_cidr = r.get('RemoteCidr', '')
        if remote_cidr:
            return f"VPN {vpn_id} CONNECTS_TO REMOTE_CIDR {remote_cidr}"
        return f"VPN {vpn_id}"
    
    # Transit Gateway 정보 추가
    elif rt == "TGW":
        tgw_id = r.get('ResourceId', '')
        return f"TGW {tgw_id}"
    
    # TGW 연결 정보 추가
    elif rt == "TGW_ATTACHMENT":
        attachment_id = r.get('ResourceId', '')
        tgw_id = r.get('ParentId', '')
        vpc_id = r.get('VpcId', '')
        return f"TGW {tgw_id} ATTACHED_TO VPC {vpc_id} VIA {attachment_id}"
    
    # 보안 그룹 정보는 관련 없을 경우 생략
    elif rt == "SG" or rt == "SG_RULE":
        return ""
    
    # 기본적으로 알려진 리소스 타입은 기본 정보 제공, 알 수 없는 타입은 빈 문자열 반환
    elif rt and r.get('ResourceId'):
        resource_id = r.get('ResourceId', '')
        cidr = r.get('IpCidr', '')
        if cidr:
            return f"{rt} {resource_id} HAS_CIDR {cidr}"
        return f"{rt} {resource_id}"
        
    return ""


def ask_llm(question: str, ctx_rows: List[Dict[str, Any]]):
    # build context from relationship lines
    context_lines: List[str] = []
    for r in ctx_rows:
        line = row_to_line(r)
        if line:
            context_lines.append(line)
    context = "\n".join(context_lines)
    prompt = PROMPT_TMPL.format(context=context, question=question)
    model = _get_chat_model()
    try:
        resp = model.invoke(prompt)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM 호출 중 오류 발생: {e}")
    response_content = resp.content if hasattr(resp, "content") else str(resp)
    # 토큰 수 계산 (단어 수 기준)
    input_tokens = len(prompt.split())
    output_tokens = len(response_content.split())
    print(f"[TOKENS] read: {input_tokens}, write: {output_tokens}")
    
    # LLM 응답은 이미 네트워크 흐름(-> 체인)을 포함하도록 프롬프트에서 지시했으므로 추가 정적 다이어그램은 제거합니다.

    return response_content


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #

def cidr_to_range(cidr: str):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return int(net.network_address), int(net.broadcast_address)
    except ValueError:
        return None, None


def ensure_collection():
    if COLLECTION in [c.name for c in client.get_collections().collections]:
        return
    client.create_collection(
        collection_name=COLLECTION,
        vectors_config=qdrant.VectorParams(size=VECTOR_SIZE, distance=qdrant.Distance.DOT),
    )


def upsert_rows(rows: List[Dict[str, Any]]):
    points = []
    for r in rows:
        cidr = r.get("IpCidr")
        if cidr:
            start, end = cidr_to_range(cidr)
            if start is None:
                # 잘못된 CIDR 문자열은 건너뜀
                continue
        else:
            # VGW / VPN 등 CIDR 없는 리소스는 -1 범위를 부여 (네트워크 검색엔 안 걸림)
            start = end = -1
        r["cidr_start"], r["cidr_end"] = start, end
        pid = int(hashlib.md5(f"{r['ResourceId']}_{cidr}".encode()).hexdigest()[:16], 16)
        points.append(qdrant.PointStruct(id=pid, vector=[0.0], payload=r))
    if points:
        client.upsert(collection_name=COLLECTION, points=points)


def account_data_exists(account: str) -> bool:
    try:
        cnt = client.count(collection_name=COLLECTION, count_filter=qdrant.Filter(must=[qdrant.FieldCondition(key="Account", match=qdrant.MatchValue(value=account))]))
        return cnt.count > 0  # type: ignore[attr-defined]
    except UnexpectedResponse:
        return False


LAST_REFRESH: Dict[str, str] = {}

def sync_account_data(account: str, regions: List[str] | None = None, force_refresh: bool = False):
    ensure_collection()
    if not force_refresh and account_data_exists(account):
        # 업데이트 시간 기록이 없으면 임시로 now()
        if account not in LAST_REFRESH:
            LAST_REFRESH[account] = datetime.now(timezone.utc).isoformat()
        return
    # gather rows via fetch_network_flow logic
    acc_dicts = {a["name"]: a for a in _load_accounts()}
    if account not in acc_dicts:
        raise HTTPException(status_code=400, detail="account.json에 없는 계정입니다.")
    acc = acc_dicts[account]
    if not nf.refresh_credentials(acc):
        raise HTTPException(status_code=500, detail="AssumeRole 실패")
    profile = acc["name"]
    rows: List[Dict[str, Any]] = []
    for region in nf.REGIONS:
        if regions and region not in regions:
            continue
        session = boto3.Session(profile_name=profile)
        ec2 = session.client("ec2", region_name=region)
        rows.extend(nf.collect_instance_rows(ec2, profile, region))
        rows.extend(nf.collect_vpc_and_subnet_rows(ec2, profile, region))
        rows.extend(nf.collect_vpn_rows(ec2, profile, region))
        rows.extend(nf.collect_vgw_rows(ec2, profile, region))
        rows.extend(nf.collect_transit_gateway_rows(ec2, profile, region))
        rows.extend(nf.collect_tgw_attachment_rows(ec2, profile, region))
        rows.extend(nf.collect_security_group_rows(ec2, profile, region))
        rows.extend(nf.collect_route_table_rows(ec2, profile, region))
    upsert_rows(rows)
    LAST_REFRESH[account] = datetime.now(timezone.utc).isoformat()


def _load_accounts() -> List[Dict[str, Any]]:
    with open(ACCOUNTS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


@app.post("/analyze")
async def analyze(inp: PromptIn):
    # refresh 플래그 및 regions에 따라 데이터 수집
    sync_account_data(inp.account_name, regions=inp.regions, force_refresh=bool(inp.refresh))

    nets = parse_networks(inp.prompt)
    if not nets:
        raise HTTPException(status_code=400, detail="프롬프트에서 네트워크를 찾을 수 없습니다. IP 주소나 CIDR 표기법을 포함해주세요.")

    # 계정 존재 확인
    try:
        with open(ACCOUNTS_JSON, "r", encoding="utf-8") as f:
            accounts = json.load(f)
        if inp.account_name not in [a["name"] for a in accounts]:
            raise ValueError
    except Exception:
        raise HTTPException(status_code=400, detail="account_name이 account.json에 없습니다.")

    rows = fetch_context_rows(inp.account_name, nets, regions=inp.regions)
    # 대상 네트워크가 private CIDR인 경우 IGW 경로 무시
    if any(n.is_private for n in nets):
        rows = [r for r in rows if not ((r.get("ResourceType")=="RT_ROUTE" and r.get("TargetType")=="IGW") or r.get("ResourceType")=="IGW")]
    if not rows:
        raise HTTPException(status_code=404, detail="해당 계정의 네트워크 정보가 Qdrant에 없습니다. 먼저 ingestion 하세요.")
    answer = ask_llm(inp.prompt, rows)
    # 질문과 답변 로깅
    log_file = os.path.join(BASE_DIR, "qa_log.txt")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | Account: {inp.account_name} | Regions: {inp.regions}\n")
        f.write(f"Q: {inp.prompt}\nA: {answer}\n\n")
    return {"answer": answer, "hits": rows, "last_refresh": LAST_REFRESH.get(inp.account_name)}


# ---- Accounts list endpoint ---- #

@app.get("/accounts")
async def list_accounts():
    with open(ACCOUNTS_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [a["name"] for a in data]

@app.get("/regions")
async def list_regions():
    return nf.REGIONS



@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/last_refresh/{account}")
async def get_last_refresh(account: str):
    return {"account": account, "last_refresh": LAST_REFRESH.get(account)}
