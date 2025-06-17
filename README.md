# Network Flow Analyzer

## 프로젝트 개요

AWS 네트워크 리소스(EC2, VPC, Subnet, Security Group 등) 정보를 수집하여 CSV로 저장하고, Qdrant 벡터DB에 인덱싱 및 검색, 거버넌스 문서 임베딩, LLM 기반 네트워크 분석 및 질의응답 기능을 제공하는 통합 분석 도구입니다.

---

## 디렉토리 구조 및 주요 파일

```
network_flow_analysis/
├── app/
│   └── main.py              # FastAPI 기반 백엔드, LLM 및 Qdrant 연동 API
├── fetch_network_flow.py    # AWS 네트워크 리소스 크롤러 (CSV로 저장)
├── ingest_to_qdrant.py      # CSV 데이터를 Qdrant에 업서트
├── test.py                  # Bedrock LLM 테스트 스크립트
├── front/
│   └── index.html           # 프론트엔드(정적 페이지)
├── governance_docs/
│   └── account.json         # 계정 정보 예시
├── requirements.txt         # 파이썬 의존성 목록
└── README.md                # 프로젝트 설명 파일
```

---

## 주요 기능

- **AWS 네트워크 정보 수집 및 CSV 저장:**
  - `fetch_network_flow.py`를 통해 여러 AWS 계정/리전의 네트워크 리소스 정보를 수집하여 CSV 파일로 저장
- **CSV → Qdrant 업서트:**
  - `ingest_to_qdrant.py`로 저장된 CSV 데이터를 Qdrant 벡터DB에 업서트
- **LLM 기반 네트워크 분석/질의응답:**
  - `app/main.py`의 FastAPI 서버에서 LLM과 Qdrant를 활용한 네트워크 질의응답 및 분석 제공
- **프론트엔드:**
  - `/front/index.html`에서 간단한 웹 UI 제공

---

## 설치 및 실행 방법

1. 파이썬 3.10+ 환경 준비
2. 의존성 설치
   ```bash
   pip install -r requirements.txt
   ```
3. AWS 인증 정보 및 계정 정보(`governance_docs/account.json`) 준비
4. 네트워크 정보 수집 (CSV 저장)
   ```bash
   python fetch_network_flow.py
   ```
5. CSV 데이터를 Qdrant에 업서트
   ```bash
   python ingest_to_qdrant.py
   ```
6. API 서버 실행
   ```bash
   uvicorn app.main:app --reload
   ```
7. 웹 UI 접속: [http://localhost:8000](http://localhost:8000)

---

## 불필요/임시 파일 정리 안내
- `__pycache__/`, `*.pyc`, `ingest_to_qdrant.py` 파일은 배포 시 제외하세요.
- 테스트용 `test.py`는 실제 운영에는 불필요할 수 있습니다.

---

## 참고
- Qdrant, AWS, LangChain, FastAPI, Bedrock 등 다양한 오픈소스 활용
- 각 파이썬 파일의 docstring 및 주석 참고 시 상세 동작 이해 가능

---

문의 및 개선 요청은 이슈로 등록해주세요.
