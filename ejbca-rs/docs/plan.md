# ejbca-rs 개발 계획

## 목표

`ejbca-rs`는 EJBCA의 CA 운영 흐름을 Rust 백엔드와 React 프론트엔드로 다시 구성하는 프로젝트다. 초기 목표는 단일 Rust 바이너리로 실행 가능한 경량 CA 관리 서버를 만들고, 이후 CMP/OCSP의 전체 ASN.1 프로토콜 호환성을 단계적으로 채우는 것이다.

## EJBCA 코드 기준 흐름

- CMP: `CmpServlet`이 HTTP POST, alias, 요청 크기, 메시지 보호 검증을 처리하고 `CmpMessageDispatcherSessionBean`이 RFC 4210 `PKIBody` 타입별 handler로 분기한다. CRMF/PKCS#10 요청은 end entity 확인 또는 RA mode 자동 등록 후 `SignSession`/`CertificateRequestSession`으로 발급된다.
- OCSP: `OCSPServlet`은 RFC 6960 HTTP GET/POST 요청을 받고 크기와 content-type을 검증한 뒤 `OcspResponseGeneratorSessionBean`에 위임한다. 응답에는 RFC 5019 cache header가 붙는다.
- CRL: `CrlCreateSessionBean`이 CA 권한/상태를 확인하고 폐기 인증서 목록으로 CRL을 생성한다. `X509CAImpl.generateCRL`은 RFC 5280 CRL number, AKI, reason code, invalidity date, delta CRL 확장 구조를 구성한다. `CrlStoreSessionBean`은 issuer/partition/delta/crlNumber 기준으로 저장하고 `CRLStoreServlet`은 `application/pkix-crl`로 제공한다.
- DB 관리: AdminWeb의 `DatabaseMaintenanceWorkerType`은 지연 시간, 만료 인증서 삭제, 만료 CRL 삭제, batch size를 설정하고 서비스 worker가 배치 단위로 실행한다.
- Validator: `KeyValidatorSessionBean`은 validator profile을 캐시하고 발급 단계별로 public key, DNS 이름, certificate, external script validator를 실행한다. 외부 script는 allowlist와 전역 enable 설정으로 제한된다.
- AdminWeb: JSF managed bean들이 EJB session을 호출한다. Rust 버전은 React UI가 동일 역할을 REST API로 호출하며, CLI subcommand도 같은 서비스 계층을 사용한다.

## 표준 매핑

- CMP: RFC 4210, RFC 4211(CRMF), PKCS#10 CSR.
- OCSP: RFC 6960, 경량 HTTP 캐싱은 RFC 5019.
- X.509 인증서/CRL: RFC 5280. CRL download endpoint는 EJBCA가 언급한 RFC 4387 스타일을 참고한다.
- 저장/감사: 모든 발급, 폐기, CRL 생성, validator 변경, 유지보수 실행은 감사 로그에 남긴다.

## Rust 모듈 분리

- `api`: HTTP 라우팅, 관리자 토큰 인증, public CRL/OCSP/CMP 엔드포인트.
- `ca`: CA 생성, 기본 CA bootstrap, CA key/cert 로딩, CA key provider 선택.
- `key_provider`: 기존 DB PEM 저장, 파일 기반 key reference, HSM/KMS CLI/에이전트 연동용 외부 command signer를 같은 로딩/서명 경계로 통합한다.
- `certs`: CSR 발급, 서버 키 생성 발급, 폐기.
- `profiles`: certificate profile, end entity profile, CMP alias, access role 설정과 기본 정책 bootstrap.
- `crl`: 폐기 인증서 기반 base, partitioned, delta CRL 생성/저장/다운로드.
- `ocsp`: 저장소 기반 JSON status와 CA 키로 서명된 RFC 6960 `BasicOCSPResponse`.
- `cmp`: RFC 4210 envelope boundary, PKIMessage DER 파서, PBM/HMAC message protection 검증, PKIBody 타입 식별, p10cr PKCS#10 발급 handler, raVerified POP 기반 ir/cr CRMF 발급 handler, CertRepMessage DER 응답, rr 폐기 handler와 RevRepContent DER 응답.
- `validators`: 발급 전 검증기. 내장 DNS/subject 룰과 HTTP webhook 외부 검증기.
- `maintenance`: 주기적 백업, 만료 인증서/CRL 삭제, DB 최적화.
- `logging`: tracing 기반 로그 레벨/출력 대상/file retention 설정.
- `metrics`: Prometheus text endpoint와 발급 이벤트/장비별 제한 집계.
- `audit`: 설정 변경, 발급, 폐기, CRL, maintenance 이벤트 조회 API/CLI/AdminWeb.
- `storage`: SQLite 저장소. Repository 경계를 유지해 PostgreSQL 등으로 교체 가능하게 한다.

## 개선점

- JVM GC pause를 피하기 위해 Rust ownership 기반으로 요청별 메모리 수명을 짧게 유지한다.
- 대량 장비 발급을 위해 Axum/Tokio 비동기 서버와 SQL connection pool을 사용한다.
- 동시 발급 요청은 설정 가능한 semaphore로 즉시 제한해 과부하 시 내부 대기열/OOM 대신 429와 metrics 실패 이벤트로 처리한다.
- JSON/CMP 요청 body 크기와 목록 조회 limit은 설정값으로 제한해 과도한 요청이 메모리와 DB 조회량을 키우지 못하게 한다.
- 인증서/CRL 큰 바이트는 DB BLOB으로 보관하되 목록 API에서는 반환하지 않고 개별 다운로드 요청에서만 반환한다.
- SQLite 백업은 WAL 파일을 직접 복사하지 않고 `VACUUM INTO`로 현재 DB connection의 일관된 snapshot 파일을 만들어 복원 가능성을 높인다.
- DB 기반 운영 설정을 둬 AdminWeb/API/CLI에서 maintenance, metrics, 로그 보존 정책을 저장하고 런타임 가능한 값은 즉시 반영한다.
- 인증서 목록은 CA/status/serial/subject/만료 시각 필터와 limit으로 조회해 대량 장비 환경에서 전체 스캔성 운영을 줄인다.
- 대량 데이터에서 자주 쓰는 인증서 목록, 만료/상태 집계, metrics 집계, certificate event purge, audit hash chain 검증 경로에 맞춘 복합/부분 인덱스를 둔다.
- 동시 발급 회귀 테스트는 실제 SQLite 저장소와 기본 CA/profile bootstrap을 사용해 serial 중복, metrics 성공/실패 집계, audit hash chain을 함께 검증한다.
- CA private key는 기본 DB 저장 외에 선택적 DB key 암호화와 파일 provider를 지원해 DB 유출 시 키 노출 범위를 줄일 수 있게 한다.
- HSM/KMS는 `command:<base64url(JSON)>` key reference로 외부 signer에 TBS bytes를 넘겨 서명만 위임하므로, 서버 프로세스에 private key를 적재하지 않아도 된다.
- 외부 command signer는 key reference별 timeout과 서명 출력 최대 크기를 제한하고, Unix에서는 별도 process group을 timeout 때 종료하며, stderr는 제한 길이만 로그로 남겨 장애 signer가 발급 worker와 메모리를 잠식하지 못하게 한다.
- 임의 shell validator 대신 HTTP webhook validator를 우선 제공해 명령 실행 위험을 줄인다.
- HTTP webhook validator는 기본/최대 timeout과 응답 byte limit을 설정값으로 제한해 외부 검증 지연이나 큰 응답이 발급 worker와 메모리를 잠식하지 못하게 한다.
- CRL/OCSP/CMP가 모두 같은 `certificates.status`, `revoked_at`, `revocation_reason`을 참조하도록 폐기 상태를 단일화한다.
- maintenance scheduler는 설정된 경우 active CA마다 base CRL을 자동 생성하고, partition count가 2 이상이면 각 partition CRL을 생성해 폐기 정보 배포 freshness를 유지한다. 최신 CRL이 충분히 유효하고 그 이후 새 폐기가 없으면 같은 scope는 건너뛰어 CRL 누적을 줄인다.
- OCSP DER 정상 응답은 짧은 `Cache-Control: public, max-age=300, no-transform`과 `Last-Modified`/`Expires`를 제공하고, malformed/unauthorized/error 응답은 `no-store`로 캐시를 막는다.
- certificate profile/end entity profile을 발급 경로 앞단에 적용해 AdminWeb/CLI에서 바꾼 정책이 실제 발급 결과에 영향을 주게 한다.
- certificate profile/end entity profile/CMP alias/access role/validator는 생성 후 삭제-재생성 없이 API/AdminWeb/CLI에서 수정할 수 있게 한다.
- CMP shared secret은 DB에 원문을 저장하지 않고 salt가 포함된 PBKDF2-SHA256 envelope로 보관하며, 기존 SHA-256 저장값은 업그레이드 호환 검증만 유지한다. 실제 검증 secret은 alias별 환경변수에서 로드해 런타임에만 사용한다.
- CMP p10cr smoke CLI는 PKCS#10 CSR 생성, RFC 4210 PKIMessage p10cr 래핑, 선택적 PBM/HMAC 보호, HTTP `application/pkixcmp` POST, cp 응답 파싱을 같은 바이너리에서 실행해 client 상호운용성 이슈를 빠르게 재현할 수 있게 한다.
- CMP issue/revoke smoke CLI는 p10cr cp 응답에서 발급 serial을 추출한 뒤 rr 요청을 생성하고 rp status 개수를 확인해 발급과 폐기 경로를 한 번에 검증한다.
- access role은 API별 권한 문자열로 분리해 읽기, 발급, 폐기, 설정, 유지보수 권한을 최소 권한으로 나눌 수 있게 한다. role API token은 salt가 포함된 PBKDF2-SHA256 envelope로 저장하고, 기존 SHA-256 저장값은 업그레이드 호환을 위해 검증만 유지한다. AdminWeb client certificate는 EJBCA의 role member처럼 issuer DN과 serial/full DN/CN/any 조건으로 access role에 매핑한다.
- 감사 로그 조회는 `audit` 권한으로 분리하고 actor/action/target/status/time 필터와 limit을 제공해 운영 추적과 대량 데이터 보호를 함께 처리한다.
- 감사 로그 삭제는 명시 설정/요청이 있을 때만 보존 기간 기준으로 batch purge해 감사 추적 보존과 디스크 관리를 분리한다.
- 감사 로그는 SHA-256 hash chain으로 저장해 row 변조와 중간 삽입/삭제를 검증하고, 보존 정책으로 앞부분이 삭제된 경우에도 남은 구간은 첫 hash row를 앵커로 검증한다.
- 인증서 발급 저장과 `certificate.issue` 감사 이벤트, 인증서 폐기 상태 변경과 `certificate.revoke` 감사 이벤트는 각각 같은 DB transaction으로 commit해 감사 저장 실패 시 인증서 상태도 rollback한다.
- CORS는 기본 비활성화하고, React dev server 등 분리 origin이 필요한 경우에만 명시한 origin allowlist로 허용한다.
- AdminWeb은 기능별 React page/component로 분리하고, 각 페이지에 사용법 매뉴얼 패널을 두며, 운영 환경에서는 mTLS 프록시가 검증한 client certificate 정보를 `/api/v1/adminweb/session`으로 확인한 뒤 certificate role member와 매칭된 권한으로 내부 관리 API를 호출하게 한다.
- 브라우저 AdminWeb 인증서는 EJBCA의 superadmin.p12처럼 서버 생성 key와 clientAuth 인증서를 PKCS#12(.p12)로 즉시 패키징해 다운로드하고, private key 원문은 DB에 저장하지 않는다.
- 서버 생성 private key가 포함된 발급 응답은 `Cache-Control: no-store`로 캐시를 막고, DER/PEM/CRL/OCSP 응답은 `X-Content-Type-Options: nosniff`로 MIME sniffing을 막는다.
- 발급 이벤트는 `certificate_events(event_type,status,device_id,ca_id,ts)`로 분리 저장해 감사 로그와 운영 집계를 분리하고, 장비별 metrics는 상위 N개로 제한해 Prometheus label 폭증을 막는다.
- 발급 latency는 `certificate_events.latency_ms`를 SQL에서 bucket 집계해 Prometheus histogram으로 노출하고 Grafana `histogram_quantile` 쿼리에 바로 연결한다.
- CA 상태별 count와 CA 인증서 만료 timestamp를 metrics로 노출해 비활성 CA와 만료 임박 CA를 Grafana/Alertmanager에서 감시할 수 있게 한다.
- Prometheus 연동은 기존 `x-admin-token` 외에 `Authorization: Bearer`도 허용해 표준 scrape 설정에서 토큰 인증을 쉽게 구성할 수 있게 한다.
- CLI 동시 발급 load test는 전체 요청 수만큼 task를 만들지 않고 고정 worker와 atomic counter로 발급 경로를 반복 호출해 테스트 도구 자체의 메모리 사용량을 제한한다.
- CLI soak test는 duration과 선택적 max total 기준으로 같은 발급 경로를 반복 호출해 장시간 안정성, 실패율, 처리량을 운영자가 같은 바이너리로 확인할 수 있게 한다.

## 단계별 진행도

- [x] Rust 프로젝트 생성
- [x] EJBCA CMP/OCSP/CRL/DB/validator 흐름 조사
- [x] SQLite 스키마와 감사 로그 설계
- [x] CA 생성 및 기본 CA bootstrap
- [x] CA key provider 경계 분리와 파일 기반 key reference 저장
- [x] DB 저장 CA private key 선택적 암호화와 import용 encrypted key reference CLI
- [x] HSM/KMS CLI/에이전트 연동용 external command signer provider
- [x] External command signer timeout/출력 크기 제한과 장애 회귀 테스트
- [x] Certificate Authorities 생성/import/수정/상태/기본 CA API/AdminWeb/CLI 설정
- [x] Certificate profile/end entity profile 저장, Admin UI, CLI, 발급 정책 적용
- [x] CMP alias 저장, Admin UI, CLI, CMP endpoint 검증 연결
- [x] Access role 저장, Admin UI, CLI, role token 기반 관리 API 인증
- [x] Certificate profile/end entity profile/CMP alias/access role/validator 수정 API/AdminWeb/CLI
- [x] 인증서 발급/폐기, CRL, validator, DB maintenance CLI 운영 명령
- [x] API별 access role 권한 검사와 role token 권한 승격 방지
- [x] access role token PBKDF2-SHA256 저장과 기존 SHA-256 호환 검증
- [x] CMP alias HMAC secret PBKDF2-SHA256 저장과 기존 SHA-256 호환 검증
- [x] 감사 로그 저장과 필터형 조회 API/AdminWeb/CLI
- [x] CSR/서버 생성 키 기반 인증서 발급
- [x] CA/status/serial/subject/만료 시각 기준 인증서 필터 조회 API/AdminWeb/CLI
- [x] 인증서 목록 경량화와 개별 PEM/DER 다운로드 API/AdminWeb/CLI
- [x] 인증서 폐기 상태 저장
- [x] base CRL 생성/저장/다운로드
- [x] partitioned CRL과 delta CRL 생성/저장/다운로드
- [x] maintenance scheduler 기반 active CA base/partitioned CRL 자동 생성
- [x] DB 백업/삭제/최적화 API와 주기적 worker
- [x] DB 기반 운영 설정 API/AdminWeb/CLI와 런타임 maintenance/metrics 반영
- [x] WAL 모드 일관성 보장을 위한 SQLite `VACUUM INTO` 백업과 복원 가능성 테스트
- [x] 로그 레벨/stdout/file/both/파일 보존 정책 설정
- [x] Prometheus/Grafana용 metrics endpoint와 발급 이벤트 스키마/인덱스
- [x] 발급 latency histogram metrics와 Grafana dashboard/Prometheus scrape 예시
- [x] CA 상태/만료 metrics와 Grafana dashboard 패널
- [x] DB pool/busy timeout과 발급 동시성 제한 설정
- [x] 요청 body 크기 제한과 목록 조회 최대 limit 설정
- [x] 대량 인증서/metrics/audit 조회와 purge 경로용 SQLite 복합/부분 인덱스
- [x] 동시 발급 회귀 테스트와 limiter 즉시 실패 metrics 검증
- [x] 실제 발급 서비스 경로를 사용하는 CLI 동시 발급 load test
- [x] duration 기반 CLI 장시간 발급 soak test
- [x] CORS 기본 비활성화와 명시적 Origin allowlist 설정
- [x] AdminWeb 기능별 페이지/컴포넌트 분리와 페이지별 사용법 매뉴얼
- [x] AdminWeb client certificate session gate API와 React 내부 접근 게이트
- [x] AdminWeb client certificate를 access role certificate member로 매핑해 토큰 없이 관리 API 권한 확인
- [x] 브라우저 import용 AdminWeb client certificate PKCS#12(.p12) 발급 API/AdminWeb/CLI
- [x] private key 응답 캐시 방지와 DER/PEM/CRL/OCSP MIME sniffing 방어 헤더
- [x] 감사 로그 보존 기간과 명시적 batch purge maintenance
- [x] 감사 로그 SHA-256 hash chain 저장과 API/AdminWeb/CLI 검증
- [x] 발급/폐기 저장과 감사 이벤트 transaction atomicity 검증
- [x] validator 생성/수정/삭제/활성화와 pre-issue 실행
- [x] external webhook validator timeout clamp와 응답 크기 제한
- [x] RFC 6960 OCSP DER 요청 검증과 오류 DER 응답
- [x] 서명된 RFC 6960 OCSP BasicOCSPResponse 생성
- [x] RFC 5019 스타일 OCSP HTTP cache/no-store header
- [x] RFC 4210 CMP PKIMessage 파서와 PKIBody 타입 식별
- [x] RFC 4210 CMP PBM/HMAC message protection 검증
- [x] RFC 4210 CMP p10cr PKCS#10 발급 handler
- [x] RFC 4210 CMP p10cr smoke CLI와 PBM/HMAC protected request 생성
- [x] RFC 4210 CMP CertRepMessage DER 응답
- [x] RFC 4210 CMP rr 폐기 handler와 RevRepContent DER 응답
- [x] RFC 4210 CMP ir/cr CRMF handler
- [x] React AdminWeb 기능 확장 및 시각 검증
