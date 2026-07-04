import {
  BookOpen,
  Database,
  FileKey,
  Home,
  KeyRound,
  ListChecks,
  LockKeyhole,
  ScrollText,
  ShieldCheck,
  SlidersHorizontal,
} from 'lucide-react';

export const emptyIssue = {
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
  { id: 'cas', label: 'CA', icon: ShieldCheck },
  { id: 'profiles', label: '프로파일', icon: SlidersHorizontal },
  { id: 'cmp', label: 'CMP', icon: KeyRound },
  { id: 'roles', label: '접근 역할', icon: LockKeyhole },
  { id: 'validators', label: 'Validator', icon: ListChecks },
  { id: 'maintenance', label: 'CRL/운영', icon: Database },
  { id: 'audit', label: '감사 로그', icon: ScrollText },
  { id: 'manual', label: '매뉴얼', icon: BookOpen },
];

export const manuals = {
  dashboard: [
    '운영 CA는 새 인증서 발급, CRL 생성, CMP alias 기본값에 사용됩니다.',
    '카운터는 API summary와 metrics 집계를 기준으로 표시됩니다.',
    '관리자 토큰은 API 권한 확인용이고, AdminWeb 내부 화면은 client certificate 게이트를 먼저 통과해야 합니다.',
  ],
  certificates: [
    'Subject DN은 예: CN=device-001,O=Example 형식으로 입력합니다.',
    'DNS SAN은 쉼표로 여러 값을 입력할 수 있으며, end entity profile의 도메인 제한을 통과해야 합니다.',
    '브라우저 mTLS용 인증서는 clientAuth EKU가 포함된 서버 키 생성 인증서를 PKCS#12(.p12)로 즉시 다운로드해 브라우저에 import합니다.',
    'CSR 발급은 PEM 형식 PKCS#10 CSR 전체를 붙여 넣습니다.',
    '목록 검색은 CA, 상태, subject 포함 문자열, serial hex, limit을 조합해 대량 데이터를 좁혀 봅니다.',
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
    'HMAC secret은 DB에 PBKDF2-SHA256 envelope로 저장되고, 런타임에는 EJBCA_RS_CMP_SECRET_ALIAS 환경변수로 제공해야 합니다.',
    'CA/profile을 비우면 현재 선택된 CA와 첫 profile 기본값을 사용합니다.',
  ],
  roles: [
    '권한은 쉼표로 구분합니다. 예: read,issue,revoke,audit,maintenance,config,ca 또는 admin.',
    'Role API token은 생성/수정 시에만 입력하고, 저장 후에는 원문을 다시 볼 수 없습니다.',
    'Certificate member는 EJBCA AdminWeb처럼 issuer DN과 serial/full DN/CN/any 조건으로 client certificate를 access role에 매핑합니다.',
    'admin 또는 * 권한은 관리자 토큰이나 이미 admin 권한을 가진 certificate role로만 부여할 수 있습니다.',
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
    '왼쪽 기능 메뉴에서 페이지를 선택하면 해당 기능의 입력값과 운영 주의사항을 볼 수 있습니다.',
    '운영 환경에서는 AdminWeb client certificate required 모드를 켜고 mTLS 프록시가 검증한 인증서만 백엔드로 전달하게 구성합니다.',
    'RA mode 운영은 CA, profile, validator, CMP alias, access role을 순서대로 묶어 장비 발급 경로를 고정합니다.',
  ],
};

export const operatorGuideSections = [
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
      '보호된 RA mode 요청은 alias HMAC secret을 설정하고 서버 실행 환경에는 EJBCA_RS_CMP_SECRET_{ALIAS} 또는 EJBCA_RS_CMP_SECRET을 제공합니다.',
      'p10cr은 PKCS#10 CSR 기반 발급, ir/cr은 CRMF raVerified POP 기준 발급, rr은 인증서 폐기 요청으로 처리합니다.',
    ],
  },
  {
    title: '5. Access role 통과 조건',
    entries: [
      'AdminWeb/API 운영자는 role token 또는 client certificate role member로 권한을 받습니다.',
      '브라우저 mTLS 인증서는 PKCS#12(.p12)로 발급해 브라우저에 import하고, access role에는 issuer DN과 serial_hex, subject_dn, common_name, any 중 하나의 match key/value를 등록합니다.',
      '장비 발급 자동화에는 read, issue, revoke, cmp, crl 같은 최소 권한 role token을 쓰고, admin 또는 * 권한은 초기 관리자나 admin certificate role에만 부여합니다.',
    ],
  },
  {
    title: '6. 운영 확인',
    entries: [
      '발급/실패/폐기 이벤트는 감사 로그와 certificate_events에 저장됩니다. Metrics 화면이나 Prometheus/Grafana에서 발급 요청, 성공, 실패, 장비별 상위 N개, latency를 확인합니다.',
      'CRL/OCSP/CMP rr은 같은 폐기 상태를 참조합니다. CRL/운영 화면에서 partitioned/delta CRL과 자동 유지보수 주기를 설정합니다.',
    ],
  },
];
