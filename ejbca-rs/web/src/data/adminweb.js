import {
  BookOpen,
  Box,
  ClipboardCheck,
  Cog,
  Database,
  ExternalLink,
  FileKey,
  Home,
  KeyRound,
  ListChecks,
  LockKeyhole,
  LogOut,
  ScrollText,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  UserPlus,
  Users,
} from 'lucide-react';

export const emptyIssue = {
  end_entity_id: '',
  approval_id: '',
  subject_dn: 'CN=device-001,O=Example',
  dns_names: 'device-001.example.com',
  validity_days: 397,
  pkcs12_password: 'changeit',
  friendly_name: 'admin-browser',
};

export const defaultValidatorDraft = {
  id: '',
  name: 'example.com allowlist',
  kind: 'dns_allowlist',
  config: '{"domains":["example.com"]}',
  enabled: true,
};

export const defaultEjbcaFeatureDraft = {
  id: '',
  feature_type: 'ca_lifecycle',
  name: 'renewal-rollover-expiration-publishing',
  status: 'active',
  config: '{"supports":["renewal","rollover","expiration_monitor","publisher_hooks"]}',
};

export const defaultEndEntityDraft = {
  id: '',
  username: 'device-001',
  subject_dn: 'CN=device-001,O=VendorA,C=KR',
  dns_names: 'device-001.vendor-a.example.com',
  email: '',
  ca_id: '',
  certificate_profile_id: '',
  end_entity_profile_id: '',
  status: 'NEW',
  password: '',
  token_type: 'USERGENERATED',
};

export const defaultApprovalDraft = {
  action: 'issue',
  target_id: '',
  request_json: '{"reason":"RA enrollment"}',
  expires_at: '',
};

export const defaultCaDraft = {
  id: '',
  name: 'iot-root-ca',
  subject_dn: 'CN=IoT Root CA,O=Example',
  validity_days: 3650,
  status: 'active',
  make_default: false,
};

export const pages = [
  { id: 'dashboard', label: '대시보드', icon: Home },
  { id: 'certificates', label: '인증서', icon: FileKey },
  { id: 'ra', label: 'RA', icon: ClipboardCheck },
  { id: 'cas', label: 'CA', icon: ShieldCheck },
  { id: 'profiles', label: '프로파일', icon: SlidersHorizontal },
  { id: 'cmp', label: 'CMP', icon: KeyRound },
  { id: 'roles', label: '접근 역할', icon: LockKeyhole },
  { id: 'ejbca', label: 'EJBCA 기능', icon: BookOpen },
  { id: 'validators', label: 'Validator', icon: ListChecks },
  { id: 'maintenance', label: 'CRL/운영', icon: Database },
  { id: 'audit', label: '감사 로그', icon: ScrollText },
  { id: 'manual', label: '매뉴얼', icon: BookOpen },
];

export const menuGroups = [
  {
    id: 'home',
    label: '홈',
    icon: Home,
    pageId: 'dashboard',
    tooltip: 'AdminWeb 첫 화면과 운영 요약으로 이동합니다.',
  },
  {
    id: 'ca-functions',
    label: 'CA 기능',
    icon: Server,
    tooltip: 'CA, CRL, certificate profile, crypto token, publisher, validator를 관리합니다.',
    items: [
      { label: 'CA 활성화', pageId: 'cas', tooltip: 'CA 상태를 확인하고 active/disabled 전환 대상을 관리합니다.' },
      { label: 'CA 구조 및 CRL', pageId: 'cas', tooltip: 'CA 계층과 CRL 생성/분할 CRL 설정을 확인합니다.' },
      { label: '인증서 프로파일', pageId: 'profiles', tooltip: '인증서 유효기간, SAN 필수 여부, 서버 키 생성 허용 여부를 설정합니다.' },
      { label: 'CA', pageId: 'cas', tooltip: '내부 CA 생성, 외부 CA 등록, renewal/rollover를 수행합니다.' },
      { label: 'Crypto Token', pageId: 'ejbca', tooltip: 'database/file/command/encrypted key reference 같은 crypto token 기능을 관리합니다.' },
      { label: 'Publisher', pageId: 'ejbca', tooltip: '발급/폐기 후 webhook 또는 file publisher로 이벤트를 내보내는 설정입니다.' },
      { label: 'Validator', pageId: 'validators', tooltip: 'DNS allow/deny, subject keyword, external webhook 검증 조건을 관리합니다.' },
    ],
  },
  {
    id: 'ra-functions',
    label: 'RA 기능',
    icon: Users,
    tooltip: 'End entity 등록, end entity profile, 장비 검색과 승인 workflow를 관리합니다.',
    items: [
      { label: 'End Entity 추가', pageId: 'ra', tooltip: '장비 username, subject DN, SAN, profile, token type을 등록합니다.' },
      { label: '인증서 발급/폐기', pageId: 'certificates', tooltip: '등록된 end entity 또는 CSR 기반으로 인증서를 발급하고 폐기합니다.' },
      { label: 'End Entity 프로파일', pageId: 'profiles', tooltip: 'Subject DN 정규식과 허용 DNS 도메인을 설정합니다.' },
      { label: 'End Entity 검색', pageId: 'ra', tooltip: '등록된 장비와 approval 요청 상태를 확인합니다.' },
    ],
  },
  {
    id: 'va-functions',
    label: 'VA 기능',
    icon: BookOpen,
    tooltip: 'OCSP responder와 검증 관련 기능을 관리합니다.',
    items: [
      { label: 'OCSP Responder', pageId: 'ejbca', tooltip: 'Internal key binding/OCSP responder parity 기능 객체를 관리합니다.' },
    ],
  },
  {
    id: 'supervision-functions',
    label: '감독 기능',
    icon: UserPlus,
    tooltip: 'Approval profile, 승인 대기열, 감사 로그를 확인합니다.',
    items: [
      { label: 'Approval 프로파일', pageId: 'ra', tooltip: '승인이 필요한 발급/폐기 action 정책을 RA 및 EJBCA 기능에서 관리합니다.' },
      { label: '승인 작업', pageId: 'ra', tooltip: 'approval 요청을 승인하거나 거절합니다.' },
      { label: '감사', pageId: 'audit', tooltip: '감사 이벤트와 hash chain 검증 결과를 확인합니다.' },
    ],
  },
  {
    id: 'system-functions',
    label: '시스템 기능',
    icon: Box,
    tooltip: 'Role, key binding, peer system, service성 작업을 관리합니다.',
    items: [
      { label: 'Role', pageId: 'roles', tooltip: 'API token 및 client certificate member를 access role에 매핑합니다.' },
      { label: 'Key Binding', pageId: 'ejbca', tooltip: 'OCSP/내부 key binding 성격의 EJBCA 기능 객체를 관리합니다.' },
      { label: 'Peer System', pageId: 'ejbca', tooltip: 'HA node, cluster node, peer connector 설정을 관리합니다.' },
      { label: 'Service', pageId: 'maintenance', tooltip: '자동 CRL 생성, 로그/메트릭 보존, 정리 작업을 설정합니다.' },
    ],
  },
  {
    id: 'system-configuration',
    label: '시스템 설정',
    icon: Cog,
    tooltip: 'Enrollment protocol, CMP alias, 시스템 운영 설정을 관리합니다.',
    items: [
      { label: 'ACME 설정', pageId: 'ejbca', tooltip: 'ACME enrollment proxy 기능 객체를 관리합니다.' },
      { label: 'Autoenroll 설정', pageId: 'ejbca', tooltip: '자동 등록과 장비 enrollment flow 설정을 관리합니다.' },
      { label: 'CMP 설정', pageId: 'cmp', tooltip: 'CMP alias, HMAC secret, CA/profile 매핑을 관리합니다.' },
      { label: 'EST 설정', pageId: 'ejbca', tooltip: 'EST simpleenroll proxy 기능 객체를 관리합니다.' },
      { label: 'SCEP 설정', pageId: 'ejbca', tooltip: 'SCEP pkcsreq proxy 기능 객체를 관리합니다.' },
      { label: '시스템 설정', pageId: 'maintenance', tooltip: '로그, metrics, retention, 자동 유지보수 설정을 관리합니다.' },
      { label: '시스템 업그레이드', pageId: 'maintenance', tooltip: 'DB 정리, optimize, 운영 점검 작업을 실행합니다.' },
      { label: '내 환경설정', pageId: 'dashboard', tooltip: '현재 AdminWeb 세션과 기본 운영 CA를 확인합니다.' },
    ],
  },
  {
    id: 'ra-web',
    label: 'RA Web',
    icon: ExternalLink,
    pageId: 'ra',
    tooltip: 'RA 화면으로 이동합니다. 장비 등록과 approval workflow를 관리합니다.',
  },
  {
    id: 'documentation',
    label: '문서',
    icon: BookOpen,
    pageId: 'manual',
    tooltip: '프로젝트 내 한국어 운영 매뉴얼을 엽니다.',
  },
  {
    id: 'logout',
    label: '로그아웃',
    icon: LogOut,
    action: 'logout',
    tooltip: '저장된 API 토큰을 지우고 홈으로 이동합니다. mTLS 세션은 브라우저/프록시에서 관리됩니다.',
  },
];

export const manuals = {
  dashboard: [
    '운영 CA는 새 인증서 발급, CRL 생성, CMP alias 기본값에 사용됩니다.',
    '카운터는 API summary와 metrics 집계를 기준으로 표시됩니다.',
    '관리자 토큰은 API 권한 확인용이고, AdminWeb 내부 화면은 client certificate 게이트를 먼저 통과해야 합니다.',
  ],
  certificates: [
    'Subject DN은 예: CN=device-001,O=Example 형식으로 입력합니다.',
    'End entity ID를 입력하면 등록된 end entity의 CA/profile/subject/SAN을 기준으로 발급합니다.',
    'Approval 기능에서 승인을 요구하도록 설정한 경우 approved 상태의 approval ID를 같이 넣어야 발급/폐기가 통과합니다.',
    'DNS SAN은 쉼표로 여러 값을 입력할 수 있으며, end entity profile의 도메인 제한을 통과해야 합니다.',
    '브라우저 mTLS용 인증서는 clientAuth EKU가 포함된 서버 키 생성 인증서를 PKCS#12(.p12)로 즉시 다운로드해 브라우저에 import합니다.',
    'CSR 발급은 PEM 형식 PKCS#10 CSR 전체를 붙여 넣습니다.',
    '목록 검색은 CA, 상태, subject 포함 문자열, serial hex, limit을 조합해 대량 데이터를 좁혀 봅니다.',
  ],
  ra: [
    'End entity는 EJBCA RA처럼 username, subject DN, SAN, CA/profile, 상태, token type을 묶어 발급 대상 장비를 등록합니다.',
    '상태가 NEW, INITIALIZED, INPROCESS, GENERATED일 때 발급 경로에 사용할 수 있고, FAILED/REVOKED/HISTORICAL은 발급에서 차단됩니다.',
    'Approval request는 issue 또는 revoke 같은 action과 target ID를 묶습니다. approved 상태이고 만료되지 않은 approval만 발급/폐기 게이트를 통과합니다.',
    '승인이 필수인 운영은 EJBCA 기능 페이지에서 approval/end_entity_lifecycle config에 {"approval_required":true,"actions":["issue","revoke"]}를 둡니다.',
  ],
  cas: [
    'CA 생성 시 name, subject DN, validity days를 입력합니다. 생성 후 subject와 기간은 바꾸지 않습니다.',
    'External CA import의 key_ref는 database/file/command/encrypted key reference를 넣습니다.',
    'disabled CA는 신규 발급 경로에서 차단됩니다. make default는 기본 발급 CA 선택에 사용됩니다.',
  ],
  profiles: [
    'Certificate profile은 유효기간, 서버 생성 키 허용 여부, SAN 필수 여부를 정의합니다.',
    'End entity profile은 Subject DN 정규식과 허용 DNS 도메인을 정의합니다.',
    'allowed DNS domains는 쉼표로 구분하며, 비워두면 도메인 제한을 적용하지 않습니다.',
  ],
  cmp: [
    'Alias는 CMP endpoint /cmp/{alias}에 쓰이며 영문/숫자/-/_ 조합을 사용합니다.',
    'HMAC secret은 DB에 PBKDF2-SHA256 envelope로 저장되고, 런타임에는 ejbca-rs.toml의 [cmp_alias_secrets] 또는 cmp_secret으로 제공합니다.',
    'CA/profile을 비우면 현재 선택된 CA와 첫 profile 기본값을 사용합니다.',
  ],
  roles: [
    '권한은 쉼표로 구분합니다. 예: read,issue,revoke,audit,maintenance,config,ca 또는 admin.',
    'Role API token은 생성/수정 시에만 입력하고, 저장 후에는 원문을 다시 볼 수 없습니다.',
    'Certificate member는 EJBCA AdminWeb처럼 issuer DN과 serial/full DN/CN/any 조건으로 client certificate를 access role에 매핑합니다.',
    'admin 또는 * 권한은 관리자 토큰이나 이미 admin 권한을 가진 certificate role로만 부여할 수 있습니다.',
  ],
  ejbca: [
    'EJBCA 기능 페이지는 CA lifecycle, crypto token, enrollment protocol, CMP flow, approval, publisher, HA node 같은 parity 기능 객체를 관리합니다.',
    'feature type은 정해진 타입 중 하나를 쓰고, config JSON에는 해당 기능의 lightweight 설정을 넣습니다.',
    'ca_lifecycle 기능은 정책 객체이고, 실제 CA renewal/rollover 실행은 CA 화면 버튼 또는 renew-ca/rollover-ca CLI와 API에서 수행합니다.',
    'cmp_auth_module의 vendor_certificate rule은 TLS proxy가 검증해 넘긴 client certificate header를 alias, subject, issuer, fingerprint, proxy secret 기준으로 검사합니다.',
    'publisher 기능은 {"type":"webhook","url":"..."} 또는 {"type":"file","path":"./data/publisher-events.ndjson"} 형태로 설정하면 발급/폐기 직후 dispatch됩니다.',
    'access_rule 기능은 {"mode":"allowlist","rules":[{"actors":["role:issuer"],"actions":["issue"],"ca_ids":["..."],"protocols":["admin_api","cmp"]}]} 형태로 CA/profile/protocol scope를 제한합니다.',
    '기능 변경에는 config 권한이 필요합니다. 조회는 read 권한으로 가능합니다.',
  ],
  validators: [
    'dns_allowlist/dns_denylist는 {"domains":["example.com"]} 형태를 사용합니다.',
    'deny_subject_keywords는 {"keywords":["test"]} 형태를 사용합니다.',
    'external_webhook은 URL, timeout_ms 등을 JSON으로 넣고 응답 크기와 timeout 제한을 받습니다.',
  ],
  maintenance: [
    '자동 유지보수는 설정된 주기마다 백업, 만료 데이터 삭제, CRL 자동 생성, optimize를 수행합니다.',
    'CRL partition_count가 2 이상이면 partitioned CRL을 생성합니다. delta CRL은 최근 폐기분 배포에 사용합니다.',
    '로그 출력은 stdout/file/both 중 선택하고 retention days/files로 파일 보존을 제한합니다.',
    'metrics device limit은 Prometheus label 폭증을 막기 위한 상위 장비 수입니다.',
  ],
  audit: [
    '감사 로그는 actor/action/target/status/details와 hash chain 검증 상태를 보여줍니다.',
    'Hash chain invalid는 중간 row 변경, 삭제, 삽입 가능성을 의미하므로 즉시 원인을 확인해야 합니다.',
  ],
  manual: [
    '상단 기능 메뉴에서 페이지를 선택하면 해당 기능의 입력값과 운영 주의사항을 볼 수 있습니다.',
    '운영 환경에서는 ejbca-rs.toml 설정 파일로 AdminWeb client certificate required 모드를 켜고 mTLS 프록시가 검증한 인증서만 백엔드로 전달하게 구성합니다.',
    'RA mode 운영은 CA, profile, validator, CMP alias, access role을 순서대로 묶어 장비 발급 경로를 고정합니다.',
  ],
};

export const pageGuides = {
  dashboard: {
    summary: '전체 CA 운영 상태, 발급 통계, 최근 감사 상태를 한 화면에서 확인하는 시작 지점입니다.',
    primaryAction: '처음 설정할 때는 CA, 프로파일, RA 등록, CMP alias, access role 순서로 진행합니다.',
    steps: ['운영 CA와 기본 profile 존재 여부 확인', '발급/실패/폐기 카운터로 이상 징후 확인', '감사 hash chain 상태 확인'],
    terms: [
      ['운영 CA', '발급, CRL 생성, CMP alias 기본값에 사용되는 현재 선택 CA입니다.'],
      ['감사 hash chain', '감사 로그가 중간에 변경되거나 삭제되지 않았는지 검증하는 연결 해시입니다.'],
    ],
    related: [
      { label: 'CA 만들기', pageId: 'cas' },
      { label: '프로파일 설정', pageId: 'profiles' },
      { label: 'RA 등록', pageId: 'ra' },
    ],
  },
  certificates: {
    summary: 'End entity, 직접 입력한 Subject DN, CSR, 브라우저 mTLS용 PKCS#12 인증서를 발급하고 폐기합니다.',
    primaryAction: '일반 장비는 end entity를 먼저 등록한 뒤 ID를 넣고 발급하는 흐름이 가장 안전합니다.',
    steps: ['운영 CA와 profile 선택 상태 확인', 'End entity ID 또는 Subject DN/CSR 입력', '발급 결과 다운로드 또는 폐기 처리'],
    terms: [
      ['Subject DN', 'CN, O, C 같은 속성으로 구성된 인증서 주체 이름입니다. 예: CN=device-001,O=VendorA,C=KR'],
      ['CSR', '장비가 만든 공개키와 Subject 정보를 담은 PKCS#10 요청입니다. private key는 장비에 남습니다.'],
      ['PKCS#12', '브라우저가 import할 수 있는 .p12 파일입니다. mTLS 관리자 인증서 배포에 사용합니다.'],
    ],
    related: [
      { label: 'End entity 등록', pageId: 'ra' },
      { label: '프로파일 제한', pageId: 'profiles' },
      { label: '감사 확인', pageId: 'audit' },
    ],
  },
  ra: {
    summary: 'RA 모드에서 장비를 end entity로 등록하고, 발급/폐기 승인 요청을 관리합니다.',
    primaryAction: '장비를 먼저 등록한 뒤 인증서 발급 화면에서 end entity ID로 발급하면 profile과 subject 검증이 일관됩니다.',
    steps: ['장비 username, Subject DN, DNS SAN 등록', '필요하면 approval request 생성', '승인 후 발급/폐기 화면에서 approval ID 사용'],
    terms: [
      ['End entity', '인증서를 받을 장비나 사용자를 뜻하며, CA/profile/subject/SAN 정책을 묶습니다.'],
      ['Approval', '발급이나 폐기 같은 민감 작업을 다른 관리자가 승인하게 만드는 workflow입니다.'],
    ],
    related: [
      { label: '인증서 발급', pageId: 'certificates' },
      { label: 'End entity profile', pageId: 'profiles' },
      { label: 'Access role', pageId: 'roles' },
    ],
  },
  cas: {
    summary: '내부 CA 생성, 외부/벤더 CA 등록, CA renewal, rollover, CRL 생성을 관리합니다.',
    primaryAction: '처음에는 default 운영 CA를 하나 만들고, 벤더 CA는 발급 CA와 trust anchor 역할을 분리해 등록합니다.',
    steps: ['CA 이름과 Subject DN 결정', '내부 생성 또는 외부 CA import 선택', 'default 여부와 active/disabled 상태 관리'],
    terms: [
      ['Renewal', '같은 CA key와 ID를 유지하면서 CA 인증서 유효기간을 갱신합니다.'],
      ['Rollover', '새 key와 새 CA를 만들어 기본 CA를 전환하는 방식입니다.'],
      ['CRL', '폐기된 인증서 목록입니다. 장비와 검증자는 이 목록으로 폐기 상태를 확인합니다.'],
    ],
    related: [
      { label: '프로파일 설정', pageId: 'profiles' },
      { label: 'CRL 운영', pageId: 'maintenance' },
      { label: 'Publisher', pageId: 'ejbca' },
    ],
  },
  profiles: {
    summary: 'Certificate profile과 End entity profile로 인증서 형식과 입력값 통과 조건을 제한합니다.',
    primaryAction: '장비 인증서 정책은 certificate profile, subject/SAN 검증은 end entity profile에 나눠 둡니다.',
    steps: ['유효기간과 SAN 필수 여부 설정', 'Subject DN 정규식 작성', '허용 DNS 도메인 목록 등록'],
    terms: [
      ['Certificate profile', '인증서 유효기간, SAN 필수 여부, 서버 키 생성 허용 여부 같은 출력 형식을 정의합니다.'],
      ['End entity profile', 'Subject DN 정규식과 DNS 도메인 제한처럼 요청 입력값 통과 조건을 정의합니다.'],
    ],
    related: [
      { label: 'Validator 설정', pageId: 'validators' },
      { label: 'CMP alias 연결', pageId: 'cmp' },
      { label: '장비 등록', pageId: 'ra' },
    ],
  },
  cmp: {
    summary: 'CMP endpoint alias에 CA, certificate profile, end entity profile, HMAC secret을 묶습니다.',
    primaryAction: '장비가 호출할 /cmp/{alias} 별로 발급 CA와 profile을 고정해 실수로 다른 정책이 적용되지 않게 합니다.',
    steps: ['alias 이름 결정', 'CA/profile/end entity profile 연결', 'HMAC secret을 DB와 설정 파일에 동일하게 반영'],
    terms: [
      ['Alias', '장비가 호출하는 CMP 엔드포인트 이름입니다. 예: /cmp/vendor-ra'],
      ['HMAC secret', 'CMP 요청 보호값입니다. DB에는 해시 envelope로 저장되고 실제 검증 값은 설정 파일에서 읽습니다.'],
    ],
    related: [
      { label: 'CA 확인', pageId: 'cas' },
      { label: '프로파일 확인', pageId: 'profiles' },
      { label: '벤더 인증서 인증', pageId: 'ejbca' },
    ],
  },
  roles: {
    summary: 'AdminWeb/API 접근 권한을 role token 또는 client certificate member 조건으로 관리합니다.',
    primaryAction: '운영자는 최소 권한 role을 만들고, 브라우저 mTLS 인증서는 issuer DN과 serial 또는 subject 조건으로 매핑합니다.',
    steps: ['권한 문자열 결정', 'API token 또는 인증서 member 조건 입력', 'admin 권한은 초기 관리자에게만 제한'],
    terms: [
      ['Role token', 'API 요청에 x-admin-token 또는 Bearer로 넣는 권한 토큰입니다. 저장 후 원문은 다시 보이지 않습니다.'],
      ['Certificate member', '브라우저/프록시가 검증한 client certificate를 issuer/serial/subject 조건으로 role에 매핑합니다.'],
    ],
    related: [
      { label: '브라우저 인증서 발급', pageId: 'certificates' },
      { label: '감사 로그', pageId: 'audit' },
      { label: 'Access rule', pageId: 'ejbca' },
    ],
  },
  ejbca: {
    summary: 'EJBCA parity 기능 객체를 관리합니다. Publisher, access rule, CMP auth, HA node, protocol proxy를 여기서 설정합니다.',
    primaryAction: '전용 화면이 아직 없는 EJBCA 기능은 feature type과 JSON config로 먼저 등록해 정책을 고정합니다.',
    steps: ['feature type 선택', 'JSON config 입력', 'active 상태 저장 후 관련 발급/폐기 경로에서 동작 확인'],
    terms: [
      ['Publisher', '인증서 발급/폐기 이벤트를 webhook 또는 file로 외부 시스템에 전달합니다.'],
      ['Access rule', 'actor/action/CA/profile/protocol 범위로 실제 작업 허용 조건을 제한합니다.'],
      ['CMP auth module', '벤더 CA나 mTLS proxy가 전달한 인증서 header를 CMP alias별로 검증합니다.'],
    ],
    related: [
      { label: 'CMP 설정', pageId: 'cmp' },
      { label: 'Role 설정', pageId: 'roles' },
      { label: '운영 설정', pageId: 'maintenance' },
    ],
  },
  validators: {
    summary: '발급 요청이 통과해도 되는지 DNS, subject keyword, external webhook으로 추가 검증합니다.',
    primaryAction: '단순 도메인 제한은 allowlist/denylist로 처리하고, OID나 벤더 DB 검증은 external webhook을 사용합니다.',
    steps: ['validator 종류 선택', 'JSON config 작성', '장비 발급 요청으로 통과/실패 로그 확인'],
    terms: [
      ['DNS allowlist', 'SAN DNS가 지정 도메인 안에 있을 때만 발급을 허용합니다.'],
      ['External webhook', '외부 시스템이 allowed/message JSON으로 발급 허용 여부를 판단하게 합니다.'],
    ],
    related: [
      { label: 'Profile 제한', pageId: 'profiles' },
      { label: '발급 테스트', pageId: 'certificates' },
      { label: '감사 로그', pageId: 'audit' },
    ],
  },
  maintenance: {
    summary: 'CRL 생성, 자동 유지보수, 로그 출력/보존, metrics retention 같은 운영 설정을 관리합니다.',
    primaryAction: '운영 전에 로그 출력 방식과 retention을 정하고, metrics device limit으로 label 폭증을 막습니다.',
    steps: ['로그 level/output/retention 설정', 'metrics와 audit retention 확인', 'CRL 자동 생성과 DB 정리 주기 설정'],
    terms: [
      ['Log output', 'stdout, file, both 중 선택합니다. container 환경은 stdout, 장기 보존은 file/both가 적합합니다.'],
      ['Metrics device limit', '장비별 Prometheus label 수를 제한해 Grafana 조회와 저장소 부하를 줄입니다.'],
      ['Delta CRL', '최근 폐기분만 담는 CRL로, 전체 CRL과 함께 운영할 수 있습니다.'],
    ],
    related: [
      { label: 'CRL 대상 CA', pageId: 'cas' },
      { label: '감사 retention', pageId: 'audit' },
      { label: 'Publisher 설정', pageId: 'ejbca' },
    ],
  },
  audit: {
    summary: '관리자 작업, 발급/폐기 결과, 실패 원인을 감사 로그와 hash chain 상태로 확인합니다.',
    primaryAction: '실패나 권한 문제를 조사할 때 actor, action, target, status, details를 먼저 봅니다.',
    steps: ['최근 실패 이벤트 확인', 'actor와 target으로 원인 추적', 'hash chain invalid 발생 시 DB 변경 여부 조사'],
    terms: [
      ['Actor', '작업을 수행한 관리자, role token, client certificate subject입니다.'],
      ['Hash chain invalid', '감사 로그 중간 변경, 삭제, 삽입 가능성을 의미합니다. 즉시 원인을 확인해야 합니다.'],
    ],
    related: [
      { label: 'Role 설정', pageId: 'roles' },
      { label: '운영 설정', pageId: 'maintenance' },
      { label: '발급 화면', pageId: 'certificates' },
    ],
  },
  manual: {
    summary: 'RA mode 운영 절차를 한 번에 읽는 문서 화면입니다. 설정 순서와 장비 발급 흐름을 확인합니다.',
    primaryAction: '처음 구축할 때는 문서의 0번부터 7번까지 순서대로 진행하고 각 화면에서 설정을 반영합니다.',
    steps: ['설정 파일 준비', 'CA/profile/validator/CMP alias 설정', '장비 등록과 access role 검증'],
    terms: [
      ['RA mode', '장비 등록과 승인 workflow를 통해 발급 정책을 통제하는 운영 방식입니다.'],
      ['Vendor CA', '장비나 벤더 RA를 인증하기 위한 외부 신뢰 anchor 또는 import된 CA입니다.'],
    ],
    related: [
      { label: '대시보드', pageId: 'dashboard' },
      { label: 'CA 기능', pageId: 'cas' },
      { label: 'CMP 설정', pageId: 'cmp' },
    ],
  },
};

export const panelDescriptions = {
  '운영 요약': '운영자가 매번 먼저 확인해야 하는 핵심 카운터입니다. 발급 실패나 폐기 수가 갑자기 늘면 감사 로그를 확인합니다.',
  '최근 감사 상태': '감사 로그와 hash chain 검증 결과입니다. invalid가 보이면 운영 데이터 변경 가능성을 조사해야 합니다.',
  '인증서 발급': '새 인증서, CSR 기반 인증서, 브라우저 mTLS용 PKCS#12 인증서를 발급합니다. 운영 CA와 profile 상태를 먼저 확인합니다.',
  '인증서 목록': '발급된 인증서를 상태, Subject, serial로 검색하고 PEM/DER 다운로드 또는 폐기를 수행합니다.',
  'End entity': 'RA mode에서 장비를 등록하는 영역입니다. 등록값은 이후 발급 요청의 기본 정책과 검증 조건이 됩니다.',
  'Approval request': '발급/폐기 같은 민감 작업에 승인 workflow를 걸 때 사용하는 요청입니다.',
  'End entity 목록': '등록된 장비 목록입니다. 발급이 안 될 때 CA/profile/status 값을 먼저 확인합니다.',
  'Approval 목록': '승인 대기, 승인됨, 반려됨, 취소됨 상태를 확인하고 처리합니다.',
  'Certificate Authority': '내부 발급 CA를 만들거나 상태를 바꿉니다. Subject DN과 유효기간은 운영 정책에 맞춰 신중히 정합니다.',
  'External CA import': '외부/벤더 CA 인증서와 key reference를 등록합니다. private key가 서버에 없어야 하면 file/command/encrypted 참조를 사용합니다.',
  'CA 목록': '등록된 CA의 상태, 기본 CA 여부, key provider, renewal/rollover 작업을 확인합니다.',
  'Certificate profile': '인증서 출력 형식과 발급 제한을 정합니다. 유효기간, SAN 필수 여부, 서버 키 생성 허용 여부가 핵심입니다.',
  'End entity profile': 'Subject DN 정규식과 DNS 도메인 allowlist로 요청 입력값을 제한합니다.',
  'Profile 목록': 'Certificate profile과 end entity profile을 함께 확인하고 CMP alias 또는 장비 등록과 연결합니다.',
  'CMP alias': '장비가 호출할 CMP endpoint에 CA/profile/HMAC secret을 연결합니다.',
  'CMP alias 목록': 'alias별 연결 CA/profile과 활성 상태를 확인합니다. 장비 장애 시 먼저 보는 목록입니다.',
  'Access role': 'AdminWeb/API 권한을 role token 또는 client certificate 조건으로 부여합니다.',
  'Access role 목록': '운영자와 장비 자동화 권한을 확인합니다. admin 권한은 최소 대상에게만 부여합니다.',
  'EJBCA 기능 객체': '전용 화면이 없는 EJBCA parity 기능을 feature type과 JSON config로 등록합니다.',
  'EJBCA 기능 목록': 'Publisher, access rule, CMP auth module, HA node 같은 기능 객체의 활성 상태를 확인합니다.',
  Validator: '발급 요청이 실제 정책을 만족하는지 추가 검증합니다. OID나 벤더 DB 검증은 external webhook을 사용합니다.',
  'Validator 목록': '등록된 validator와 활성 상태를 확인합니다. 실패 원인은 감사 로그와 발급 실패 메시지에서 함께 확인합니다.',
  '운영 설정': '자동 유지보수, 로그, metrics, retention을 설정합니다. 변경 후 재시작 필요 항목이 있는지 확인합니다.',
  'CRL 및 수동 유지보수': 'CRL 생성, partition/delta CRL, DB 정리, optimize를 수동으로 실행합니다.',
  '감사 로그': '누가 무엇을 했는지 추적합니다. 권한 오류, 발급 실패, 폐기 이력을 조사할 때 사용합니다.',
};

export const operatorGuideSections = [
  {
    title: '0. 설정 파일 준비',
    entries: [
      'config/ejbca-rs.example.toml을 ejbca-rs.toml로 복사하고 bind_addr, admin_token, 로그, metrics, maintenance, cmp_secret, cmp_alias_secrets를 운영값으로 바꿉니다.',
      '서버는 cargo run -- --config-file ejbca-rs.toml serve로 시작합니다. --config-file을 생략하면 현재 디렉터리의 ejbca-rs.toml을 자동으로 읽습니다.',
      '가상 장비 시뮬레이션은 config/virtual-device.example.toml을 복사해 device_id, alias, subject_dn, dns_names를 설정한 뒤 simulate-device로 실행합니다.',
    ],
  },
  {
    title: '1. CA와 벤더 CA 등록',
    entries: [
      '운영 발급 CA는 CA 화면에서 생성하거나 import합니다. 장비 인증서를 실제로 서명할 CA를 default 또는 CMP alias의 CA로 지정합니다.',
      '벤더가 제공한 외부 CA 인증서와 key reference가 있으면 CA import로 등록합니다. private key가 서버에 없어야 하는 경우 file, encrypted, command key reference를 사용합니다.',
      '벤더 CA를 단순 신뢰 anchor로만 쓰는 경우에는 AdminWeb mTLS proxy trust store나 external webhook validator에서 검증하고, 발급 CA와 분리해 운용합니다.',
    ],
  },
  {
    title: '2. 장비 인증서 형식 결정',
    entries: [
      '권장 Subject DN 예시는 CN={deviceId},O={vendor},C=KR 입니다. OU, serialNumber, UID 또는 2.5.4.x 계열 OID가 필요하면 DN 문자열에 포함하고 end entity profile regex로 제한합니다.',
      'DNS SAN은 장비 FQDN을 쉼표로 입력합니다. IP, URI, custom extension OID 같은 추가 검증은 현재 external_webhook validator에서 CSR/subject/SAN을 받아 검사하는 방식으로 처리합니다.',
      'certificate profile은 validity days, server generated key 허용 여부, SAN 필수 여부를 정합니다. 장비가 CSR을 올리는 RA mode에서는 CSR 발급을 쓰고, 서버가 키를 만들어 브라우저에 넣는 AdminWeb 인증서는 PKCS#12 발급을 씁니다.',
    ],
  },
  {
    title: '3. 통과 조건 설정',
    entries: [
      'end entity profile의 subject_regex로 CN/O/C 순서와 값을 제한합니다. 예: ^CN=device-[A-Za-z0-9-]+,O=VendorA,C=KR$',
      'allowed_dns_domains에는 vendor-a.example.com 같은 허용 도메인을 넣습니다. 비워두면 DNS SAN 도메인 제한을 하지 않습니다.',
      'validator는 dns_allowlist, dns_denylist, deny_subject_keywords, external_webhook을 지원합니다. OID, 벤더 DB, serialNumber, CSR extension 검증은 webhook에서 allowed/message JSON으로 판정합니다.',
    ],
  },
  {
    title: '4. CMP alias와 RA mode 장비 발급',
    entries: [
      'CMP alias는 /cmp/{alias} 엔드포인트 이름입니다. alias에 CA, certificate profile, end entity profile을 묶어 장비가 어떤 정책으로 발급받는지 고정합니다.',
      '보호된 RA mode 요청은 alias HMAC secret을 설정하고 ejbca-rs.toml의 [cmp_alias_secrets] 또는 cmp_secret에 같은 값을 둡니다.',
      '벤더 CA 기반 RA는 TLS proxy trust store에서 client certificate 체인을 검증하고, cmp_auth_module vendor_certificate rule에서 x-cmp-client-cert-pem 같은 header의 subject/issuer/fingerprint를 확인합니다.',
      'p10cr은 PKCS#10 CSR 기반 발급, ir/cr은 CRMF raVerified POP 기준 발급, kur은 CRMF 갱신, certConf는 pkiconf ack, rr은 인증서 폐기 요청으로 처리합니다.',
      'CMP wire protocol이 필요 없는 경우 /est/{alias}/simpleenroll, /scep/{alias}/pkcsreq, /acme/{alias}/finalize 경량 CSR proxy가 같은 alias CA/profile/validator/access_rule을 사용합니다.',
      'simulate-device는 장비 private key, CSR PEM, CMP 요청 DER, CMP 응답 DER, summary.json을 출력해 alias/profile/validator 조건을 한 번에 검증합니다.',
    ],
  },
  {
    title: '5. End entity와 승인 workflow',
    entries: [
      'RA 화면에서 장비 username, subject DN, DNS SAN, CA/profile, 상태를 등록합니다. 발급 화면에서 end entity ID를 넣으면 등록값으로 요청이 보정됩니다.',
      'approval_required를 켠 경우 RA 화면에서 action=issue, target_id=<END_ENTITY_ID> approval을 만들고 승인한 뒤 발급 요청에 approval ID를 넣습니다.',
      '폐기도 action=revoke, target_id=<CERTIFICATE_ID> approval을 승인한 뒤 폐기 요청에 approval ID를 넣는 방식으로 통제할 수 있습니다.',
    ],
  },
  {
    title: '6. Access role 통과 조건',
    entries: [
      'AdminWeb/API 운영자는 role token 또는 client certificate role member로 권한을 받습니다.',
      '브라우저 mTLS 인증서는 PKCS#12(.p12)로 발급해 브라우저에 import하고, access role에는 issuer DN과 serial_hex, subject_dn, common_name, any 중 하나의 match key/value를 등록합니다.',
      'CA/profile/protocol별 세부 scope는 access_rule 기능 객체에서 actor/action/ca_ids/profile_ids/protocols rule로 좁힙니다.',
      '장비 발급 자동화에는 read, issue, revoke, cmp, crl 같은 최소 권한 role token을 쓰고, admin 또는 * 권한은 초기 관리자나 admin certificate role에만 부여합니다.',
    ],
  },
  {
    title: '7. 운영 확인',
    entries: [
      'CA renewal은 기존 CA ID와 key를 유지하며 CA 인증서를 갱신하고, rollover는 새 key와 새 CA를 생성해 기본 CA로 전환하거나 기존 CA를 비활성화할 수 있습니다.',
      '발급/실패/폐기 이벤트는 감사 로그와 certificate_events에 저장됩니다. Metrics 화면이나 Prometheus/Grafana에서 발급 요청, 성공, 실패, 장비별 상위 N개, latency를 확인합니다.',
      'publisher 기능 객체를 webhook/file type으로 활성화하면 발급/폐기 이벤트를 외부 시스템이나 NDJSON 파일에 게시합니다.',
      'cluster_node 기능 객체는 HA 정책 설명이고, 실제 node heartbeat는 /api/v1/cluster/nodes 또는 cluster-heartbeat CLI로 node_id, role, status, metadata를 저장합니다.',
      'CRL/OCSP/CMP rr은 같은 폐기 상태를 참조합니다. CRL/운영 화면에서 partitioned/delta CRL과 자동 유지보수 주기를 설정합니다.',
    ],
  },
];
