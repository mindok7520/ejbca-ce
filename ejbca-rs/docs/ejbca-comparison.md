# ejbca-rs와 EJBCA 기능 비교

이 문서는 현재 `ejbca-rs` 구현을 EJBCA의 AdminWeb/CLI/프로토콜 운용 모델과 비교한 것입니다. 참고 기준은 Keyfactor EJBCA 공식 문서의 [CMP 개요](https://docs.keyfactor.com/ejbca/latest/cmp), [CMP Operations Guide](https://docs.keyfactor.com/ejbca/latest/cmp-operations-guide), [3GPP CMP Operations](https://docs.keyfactor.com/ejbca/latest/3gpp-cmp-operations), [End Entity Profiles Overview](https://docs.keyfactor.com/ejbca/latest/end-entity-profiles-overview)입니다.

## 요약

`ejbca-rs`는 장비 RA mode 발급에 필요한 핵심 경로를 작게 구현한 서버입니다. CA, certificate profile, end entity profile, CMP alias, access role, CRL, OCSP, validator, 감사 로그, metrics를 한 프로세스 안에서 제공합니다. EJBCA는 훨씬 넓은 PKI 제품으로, approvals, publishers, crypto token/HSM, 세밀한 access rules, 다양한 enrollment protocol, CA lifecycle, clustering/HA 운용 기능을 포함합니다.

## 유사한 부분

| 영역 | EJBCA | ejbca-rs |
| --- | --- | --- |
| CA 관리 | AdminWeb/CLI에서 CA를 만들고 발급 CA를 선택 | AdminWeb/API/CLI에서 CA 생성, import, 상태 변경, default CA 지정 |
| Certificate profile | 인증서 내용, key usage, extension, 유효기간 등을 제한 | 유효기간, key usage, extended key usage, SAN 필수, 서버 생성 key 허용 여부 제한 |
| End entity profile | Subject DN 필드와 profile/CA 접근 범위를 제한 | Subject DN regex, DNS domain allowlist, 기본 certificate profile 연결 |
| CMP alias | alias별 endpoint와 CA/profile/auth 설정 | `/cmp/{alias}` endpoint와 CA/profile/HMAC secret 설정 |
| CMP RA mode | 신뢰된 RA가 end entity를 사전 등록 없이 발급 요청 | alias secret과 profile/validator 검증 통과 시 CSR/CRMF 기반 발급 |
| CMP p10cr | PKCS#10 CSR을 CMP 메시지로 전달 | PKCS#10 CSR 기반 p10cr 발급과 DER `CertRepMessage` 응답 |
| CMP rr | RA가 CMP revoke request 전송 | serial 기반 rr 요청 처리와 `RevRepContent` 응답 |
| CRL | base/delta/partition 등 CRL 운용 | base/partitioned/delta CRL 생성, 저장, 다운로드, 자동 생성 |
| OCSP | RFC 6960 OCSP 응답 | POST/GET DER 요청과 서명된 BasicOCSPResponse |
| Access role | 인증서/토큰 기반 role member와 access rules | API token, admin token, AdminWeb client certificate member 매핑 |
| Validator | key/certificate/external validator로 발급 전 검증 | subject/DNS validator와 external webhook validator |
| Audit | 보안 감사 로그 | 감사 이벤트 저장, 필터 조회, SHA-256 hash chain 검증 |
| Metrics | 운영 모니터링 연동 가능 | Prometheus `/metrics`, Grafana dashboard 예시, 발급/실패/latency/장비별 집계 |

## 다른 부분과 경량 parity 구현 상태

| 영역 | EJBCA 차이 | ejbca-rs 경량 parity 구현 |
| --- | --- | --- |
| 제품 범위 | Enterprise PKI 전반을 다루는 성숙한 CA 제품 | `product_scope` 기능 객체로 경량 enterprise PKI 표면을 선언하고 AdminWeb/API/CLI에서 관리 |
| CA lifecycle | CA renewal, rollover, expiration handling, publishing 등 풍부 | `ca_lifecycle` 기능 객체로 정책을 관리하고, API/CLI/AdminWeb에서 같은 key renewal과 새 key rollover를 실행. audit/만료 정보와 연동 |
| Crypto token/HSM | PKCS#11, crypto token 관리, key binding 등 제공 | `crypto_token`, `key_binding` 기능 객체와 database/file/encrypted/command key provider를 관리. PKCS#11/HSM은 `command:` signer bridge로 실제 서명 프로세스에 연결 |
| Enrollment protocol | CMP, EST, SCEP, ACME 등 다양한 protocol | CMP wire 처리와 함께 `/est/{alias}/simpleenroll`, `/scep/{alias}/pkcsreq`, `/acme/{alias}/finalize` 경량 CSR proxy endpoint를 제공. alias의 CA/profile/validator/access_rule을 재사용 |
| CMP 인증 모듈 | HMAC, EndEntityCertificate, vendor certificate mode, 3GPP 흐름 등 다양 | HMAC/PBM 검증과 `cmp_auth_module` 기반 EndEntityCertificate/vendor certificate 정책을 지원. vendor mode는 TLS proxy가 검증한 client certificate header를 alias별 subject/issuer/fingerprint/proxy secret으로 검사 |
| CMP 세부 기능 | client mode, RA mode, certConf/implicitConfirm, KUR 등 폭넓은 구현 | `cmp_flow` 기능 객체와 wire handler로 p10cr/ir/cr/kur/rr/certConf를 처리. implicitConfirm은 certConf 생략 허용 정책으로 경량 운용 |
| End entity 상태 | end entity 생성/상태/비밀번호/승인 workflow | `end_entity_lifecycle` 기능 객체와 end entity CRUD/상태/비밀번호/approval 연동으로 발급 대상 lifecycle 관리 |
| Access rules | CA별, profile별, protocol별 세밀한 rule tree | `access_rule` 기능 객체로 actor/action/CA/certificate profile/end entity profile/protocol scope 정책을 관리하고 발급/폐기 경로에서 enforce. 기존 role permission은 1차 권한으로 유지 |
| Approvals | 다단계 승인과 request workflow | `approval` 기능 객체와 approval request/decision 테이블을 제공하고 issue/revoke 요청에서 승인 ID와 상태를 검사 |
| Publishers | LDAP/AD/VA/publisher 등 외부 게시 | `publisher` 기능 객체로 LDAP/AD/VA/webhook/file publisher 설정을 관리. `webhook`과 `file` publisher는 발급/폐기 직후 dispatch되고 감사 로그에 결과를 남김 |
| DB protection | EJBCA의 보안 감사/DB protection 모델 | `db_protection` 기능 객체와 기존 audit hash chain으로 보호 대상과 알고리즘을 관리 |
| HA/cluster | 운영 환경의 clustering/peer/VA 구조 | `cluster_node` 기능 객체와 `/api/v1/cluster/nodes` heartbeat/status API, CLI로 node id/role/status/metadata를 관리. DB-level replication은 외부 SQLite/스토리지 HA 구성에 위임 |
| AdminWeb | 기능이 매우 많은 관리 UI | `EJBCA 기능` AdminWeb 페이지에서 위 기능 객체를 관리하고, React 페이지별 분리 구조를 유지 |

## EJBCA parity 기능 객체

`ejbca_features` 테이블은 EJBCA의 넓은 운영 기능을 경량 설정 객체로 저장합니다. API는 `/api/v1/ejbca/features`, CLI는 `list-ejbca-features`, `create-ejbca-feature`, `update-ejbca-feature`, `delete-ejbca-feature`를 사용합니다. 기본 bootstrap은 다음 feature type을 자동 생성합니다.

- `product_scope`
- `ca_lifecycle`
- `crypto_token`
- `key_binding`
- `enrollment_protocol`
- `cmp_auth_module`
- `cmp_flow`
- `end_entity_lifecycle`
- `access_rule`
- `approval`
- `publisher`
- `db_protection`
- `cluster_node`
- `adminweb_extension`

## RA mode 매핑

EJBCA 공식 문서는 CMP alias가 alias별 endpoint와 설정을 제공하고, RA mode에서 신뢰된 RA가 사전 등록 없이 end entity 발급을 요청하는 모델을 설명합니다. `ejbca-rs`에서는 이 구조를 다음처럼 매핑합니다.

| EJBCA 설정 개념 | ejbca-rs 설정 |
| --- | --- |
| CMP Operational Mode = RA Mode | CMP alias를 만들고 `/cmp/{alias}`로 요청 |
| CMP Authentication Module = HMAC | alias 생성 시 `--hmac-secret`, 런타임 `cmp_secret` 또는 `[cmp_alias_secrets]` |
| RA CA Name | alias의 `ca_id` |
| RA Certificate Profile | alias의 `certificate_profile_id` |
| RA End Entity Profile | alias의 `end_entity_profile_id` |
| DN part/name generation policy | end entity profile `subject_regex`와 validator |
| Vendor CA trust | 현재는 mTLS proxy trust store 또는 external webhook validator에서 검증 |
| Access rules | access role permissions와 certificate member/token |

## 현재 권장 사용 경로

1. `config/ejbca-rs.example.toml`을 `ejbca-rs.toml`로 복사해 서버 시작 설정, 로그, metrics, maintenance, CMP secret을 고정합니다.
2. AdminWeb 또는 CLI에서 운영 발급 CA를 생성합니다.
3. 벤더 CA가 실제 발급 CA로 필요하면 import하고, 신뢰 anchor 용도이면 mTLS proxy 또는 webhook validator에 둡니다.
4. 장비 인증서의 subject/SAN/유효기간/key usage를 certificate profile과 end entity profile로 제한합니다.
5. CN/O/C/OID, 제조사 장비 DB, serialNumber 같은 상세 정책은 external webhook validator로 검증합니다.
6. CMP alias에 발급 CA/profile/secret을 묶고, 설정 파일 `[cmp_alias_secrets]`에 같은 secret을 둡니다.
7. `simulate-device`로 CSR 기반 CMP p10cr 발급을 검증합니다.
8. 운영자는 AdminWeb client certificate 또는 role token으로 access role 조건을 만족해야 관리 API를 호출합니다.

## 설계상 의도

EJBCA와 완전히 같은 제품을 만드는 것이 아니라, 장비 발급 RA mode에 필요한 핵심 운영면을 Rust로 작게 유지하는 것이 현재 목표입니다. 그래서 EJBCA의 복잡한 end entity lifecycle, approvals, publishers, multi-protocol enrollment 전체를 바로 복제하지 않고, CA/profile/alias/validator/access role/metrics/audit를 명확히 분리해 확장 가능한 기반을 둡니다.
