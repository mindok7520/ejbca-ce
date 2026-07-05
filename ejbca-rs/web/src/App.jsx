import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { RefreshCw } from 'lucide-react';
import {
  AdminSessionBar,
  AdminWebEntry,
  ContextBar,
  GuidancePanel,
  MainNavigation,
  PageHeader,
} from './components/common';
import {
  defaultApprovalDraft,
  defaultCaDraft,
  defaultEjbcaFeatureDraft,
  defaultEndEntityDraft,
  defaultValidatorDraft,
  emptyIssue,
  menuGroups,
  pages,
} from './data/adminweb';
import { AuditPage } from './pages/AuditPage';
import { CaPage } from './pages/CaPage';
import { CertificatesPage } from './pages/CertificatesPage';
import { CmpPage } from './pages/CmpPage';
import { DashboardPage } from './pages/DashboardPage';
import { EjbcaFeaturesPage } from './pages/EjbcaFeaturesPage';
import { MaintenancePage } from './pages/MaintenancePage';
import { ManualPage } from './pages/ManualPage';
import { ProfilesPage } from './pages/ProfilesPage';
import { RaPage } from './pages/RaPage';
import { RolesPage } from './pages/RolesPage';
import { ValidatorsPage } from './pages/ValidatorsPage';
import './styles.css';

function App() {
  const [token, setToken] = useState(localStorage.getItem('ejbca-rs-token') || '');
  const [activePage, setActivePage] = useState(localStorage.getItem('ejbca-rs-page') || 'dashboard');
  const [adminSession, setAdminSession] = useState(null);
  const [sessionChecking, setSessionChecking] = useState(true);
  const [summary, setSummary] = useState(null);
  const [cas, setCas] = useState([]);
  const [certs, setCerts] = useState([]);
  const [crls, setCrls] = useState([]);
  const [validators, setValidators] = useState([]);
  const [maintenanceConfig, setMaintenanceConfig] = useState(null);
  const [certificateProfiles, setCertificateProfiles] = useState([]);
  const [endEntityProfiles, setEndEntityProfiles] = useState([]);
  const [cmpAliases, setCmpAliases] = useState([]);
  const [accessRoles, setAccessRoles] = useState([]);
  const [endEntities, setEndEntities] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [ejbcaFeatures, setEjbcaFeatures] = useState([]);
  const [auditEvents, setAuditEvents] = useState([]);
  const [auditChain, setAuditChain] = useState(null);
  const [selectedCaId, setSelectedCaId] = useState('');
  const [certFilter, setCertFilter] = useState({
    ca_id: '',
    status: '',
    subject: '',
    serial_hex: '',
    limit: 50,
  });
  const [issue, setIssue] = useState(emptyIssue);
  const [csr, setCsr] = useState('');
  const [caDraft, setCaDraft] = useState(defaultCaDraft);
  const [caImportDraft, setCaImportDraft] = useState({
    name: 'external-root-ca',
    cert_pem: '',
    key_ref: '',
  });
  const [crlDraft, setCrlDraft] = useState({
    validity_days: 7,
    is_delta: false,
    partition_index: -1,
    partition_count: 1,
  });
  const [certificateProfileDraft, setCertificateProfileDraft] = useState({
    id: '',
    name: 'iot-device-default',
    validity_days: 397,
    allow_server_generated_key: true,
    require_san: false,
  });
  const [endEntityProfileDraft, setEndEntityProfileDraft] = useState({
    id: '',
    name: 'iot-end-entity',
    subject_regex: '^CN=[^,]+(,.*)?$',
    allowed_dns_domains: 'example.com',
    default_certificate_profile_id: '',
  });
  const [cmpAliasDraft, setCmpAliasDraft] = useState({
    id: '',
    alias: 'iot',
    ca_id: '',
    certificate_profile_id: '',
    end_entity_profile_id: '',
    enabled: true,
    hmac_secret: '',
    clear_hmac_secret: false,
  });
  const [accessRoleDraft, setAccessRoleDraft] = useState({
    id: '',
    name: 'operator',
    permissions: 'admin',
    api_token: '',
    certificate_issuer_dn: '',
    certificate_match_key: 'serial_hex',
    certificate_match_value: '',
    clear_api_token: false,
    clear_certificate_member: false,
  });
  const [endEntityDraft, setEndEntityDraft] = useState(defaultEndEntityDraft);
  const [approvalDraft, setApprovalDraft] = useState(defaultApprovalDraft);
  const [validatorDraft, setValidatorDraft] = useState(defaultValidatorDraft);
  const [ejbcaFeatureDraft, setEjbcaFeatureDraft] = useState(defaultEjbcaFeatureDraft);
  const [maintenanceDraft, setMaintenanceDraft] = useState({
    enabled: false,
    interval_seconds: 3600,
    backup: false,
    purge_expired_certificates: false,
    purge_expired_crls: false,
    purge_metric_events: true,
    purge_audit_events: false,
    optimize: false,
    generate_crls: false,
    crl_validity_days: 7,
    crl_partition_count: 1,
    older_than_days: 30,
    batch_size: 100,
    metrics_enabled: true,
    metrics_public: false,
    metrics_device_limit: 100,
    metrics_event_retention_days: 90,
    audit_event_retention_days: 365,
    log_level: 'info',
    log_output: 'stdout',
    log_retention_days: 14,
    log_retention_files: 30,
  });
  const [status, setStatus] = useState('');

  const currentCa = useMemo(
    () => cas.find((ca) => ca.id === selectedCaId) || cas[0],
    [cas, selectedCaId],
  );
  const pageMeta = pages.find((page) => page.id === activePage) || pages[0];
  const adminAccessGranted = Boolean(adminSession?.authenticated || adminSession?.required === false);
  const headers = useMemo(() => {
    const value = {
      'content-type': 'application/json',
    };
    if (token.trim()) {
      value['x-admin-token'] = token.trim();
    }
    return value;
  }, [token]);

  useEffect(() => {
    refreshAdminSession();
  }, []);

  useEffect(() => {
    localStorage.setItem('ejbca-rs-page', activePage);
  }, [activePage]);

  useEffect(() => {
    if (token) {
      localStorage.setItem('ejbca-rs-token', token);
    } else {
      localStorage.removeItem('ejbca-rs-token');
    }
    if (adminAccessGranted) {
      refreshAll();
    }
  }, [token, adminAccessGranted]);

  useEffect(() => {
    if (cas.length && !cas.some((ca) => ca.id === selectedCaId)) {
      setSelectedCaId(cas[0].id);
    }
  }, [cas, selectedCaId]);

  useEffect(() => {
    if (!maintenanceConfig) return;
    setMaintenanceDraft({
      enabled: Boolean(maintenanceConfig.enabled),
      interval_seconds: maintenanceConfig.interval_seconds,
      backup: Boolean(maintenanceConfig.backup),
      purge_expired_certificates: Boolean(maintenanceConfig.purge_expired_certificates),
      purge_expired_crls: Boolean(maintenanceConfig.purge_expired_crls),
      purge_metric_events: true,
      purge_audit_events: Boolean(maintenanceConfig.purge_audit_events),
      optimize: Boolean(maintenanceConfig.optimize),
      generate_crls: Boolean(maintenanceConfig.generate_crls),
      crl_validity_days: maintenanceConfig.crl_validity_days,
      crl_partition_count: maintenanceConfig.crl_partition_count,
      older_than_days: maintenanceConfig.older_than_days,
      batch_size: maintenanceConfig.batch_size,
      metrics_enabled: Boolean(maintenanceConfig.metrics_enabled),
      metrics_public: Boolean(maintenanceConfig.metrics_public),
      metrics_device_limit: maintenanceConfig.metrics_device_limit,
      metrics_event_retention_days: maintenanceConfig.metrics_event_retention_days,
      audit_event_retention_days: maintenanceConfig.audit_event_retention_days,
      log_level: maintenanceConfig.log_level || 'info',
      log_output: maintenanceConfig.log_output || 'stdout',
      log_retention_days: maintenanceConfig.log_retention_days,
      log_retention_files: maintenanceConfig.log_retention_files,
    });
  }, [maintenanceConfig]);

  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { ...headers, ...(options.headers || {}) },
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({ error: response.statusText }));
      throw new Error(body.error || response.statusText);
    }
    if (response.status === 204) return null;
    return response.json();
  }

  async function refreshAdminSession() {
    setSessionChecking(true);
    try {
      const response = await fetch('/api/v1/adminweb/session');
      const data = await response.json();
      setAdminSession(data);
      setStatus(data.detail || 'AdminWeb 접근 확인 완료');
    } catch (error) {
      setAdminSession({ required: true, authenticated: false, detail: error.message });
      setStatus(error.message);
    } finally {
      setSessionChecking(false);
    }
  }

  function certificateListPath() {
    const params = new URLSearchParams();
    params.set('limit', String(certFilter.limit || 50));
    if (certFilter.ca_id) params.set('ca_id', certFilter.ca_id);
    if (certFilter.status) params.set('status', certFilter.status);
    if (certFilter.subject.trim()) params.set('subject', certFilter.subject.trim());
    if (certFilter.serial_hex.trim()) params.set('serial_hex', certFilter.serial_hex.trim());
    return `/api/v1/certificates?${params.toString()}`;
  }

  async function refreshAll() {
    try {
      const [
        summaryData,
        caData,
        certData,
        crlData,
        validatorData,
        maintenanceData,
        certProfileData,
        endEntityProfileData,
        cmpAliasData,
        accessRoleData,
        endEntityData,
        approvalData,
        ejbcaFeatureData,
        auditData,
        auditChainData,
      ] = await Promise.all([
        api('/api/v1/summary'),
        api('/api/v1/cas'),
        api(certificateListPath()),
        api('/api/v1/crls?limit=20'),
        api('/api/v1/validators'),
        api('/api/v1/maintenance/config'),
        api('/api/v1/certificate-profiles'),
        api('/api/v1/end-entity-profiles'),
        api('/api/v1/cmp-aliases'),
        api('/api/v1/access-roles'),
        api('/api/v1/end-entities?limit=100'),
        api('/api/v1/approvals?limit=100'),
        api('/api/v1/ejbca/features?limit=200'),
        api('/api/v1/audit-events?limit=50'),
        api('/api/v1/audit-events/verify'),
      ]);
      setSummary(summaryData);
      setCas(caData);
      setCerts(certData);
      setCrls(crlData);
      setValidators(validatorData);
      setMaintenanceConfig(maintenanceData);
      setCertificateProfiles(certProfileData);
      setEndEntityProfiles(endEntityProfileData);
      setCmpAliases(cmpAliasData);
      setAccessRoles(accessRoleData);
      setEndEntities(endEntityData);
      setApprovals(approvalData);
      setEjbcaFeatures(ejbcaFeatureData);
      setAuditEvents(auditData);
      setAuditChain(auditChainData);
      setStatus('동기화 완료');
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function issueGenerated() {
    try {
      const result = await api('/api/v1/certificates/issue', {
        method: 'POST',
        body: JSON.stringify({
          ca_id: currentCa?.id,
          certificate_profile_id: certificateProfiles[0]?.id,
          end_entity_profile_id: endEntityProfiles[0]?.id,
          end_entity_id: issue.end_entity_id || undefined,
          approval_id: issue.approval_id || undefined,
          subject_dn: issue.subject_dn,
          dns_names: issue.dns_names.split(',').map((value) => value.trim()).filter(Boolean),
          validity_days: Number(issue.validity_days),
        }),
      });
      setStatus(`발급 완료: ${result.serial_hex}`);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function issueBrowserCertificate() {
    try {
      const response = await fetch('/api/v1/certificates/issue-pkcs12', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          ca_id: currentCa?.id,
          certificate_profile_id: certificateProfiles[0]?.id,
          end_entity_profile_id: endEntityProfiles[0]?.id,
          end_entity_id: issue.end_entity_id || undefined,
          approval_id: issue.approval_id || undefined,
          subject_dn: issue.subject_dn,
          dns_names: issue.dns_names.split(',').map((value) => value.trim()).filter(Boolean),
          validity_days: Number(issue.validity_days),
          pkcs12_password: issue.pkcs12_password,
          friendly_name: issue.friendly_name,
        }),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({ error: response.statusText }));
        throw new Error(body.error || response.statusText);
      }
      const blob = await response.blob();
      const disposition = response.headers.get('content-disposition') || '';
      const match = disposition.match(/filename="([^"]+)"/);
      const filename = match?.[1] || `${issue.friendly_name || 'browser-certificate'}.p12`;
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setStatus(`브라우저 인증서 다운로드 완료: ${filename}`);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function issueCsr() {
    try {
      const result = await api('/api/v1/certificates/issue-csr', {
        method: 'POST',
        body: JSON.stringify({
          ca_id: currentCa?.id,
          certificate_profile_id: certificateProfiles[0]?.id,
          end_entity_profile_id: endEntityProfiles[0]?.id,
          end_entity_id: issue.end_entity_id || undefined,
          approval_id: issue.approval_id || undefined,
          csr_pem: csr,
          validity_days: 397,
        }),
      });
      setStatus(`CSR 발급 완료: ${result.serial_hex}`);
      setCsr('');
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function revoke(id) {
    try {
      await api(`/api/v1/certificates/${id}/revoke`, {
        method: 'POST',
        body: JSON.stringify({ reason: 'key_compromise', approval_id: issue.approval_id || undefined }),
      });
      setStatus('폐기 완료');
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function downloadCertificate(id, format = 'pem') {
    try {
      const response = await fetch(`/api/v1/certificates/${id}/download?format=${format}`, { headers });
      if (!response.ok) {
        const body = await response.json().catch(() => ({ error: response.statusText }));
        throw new Error(body.error || response.statusText);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${id}.${format === 'der' ? 'cer' : 'pem'}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setStatus(`인증서 ${format.toUpperCase()} 다운로드 완료`);
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function generateCrl() {
    try {
      const result = await api('/api/v1/crls/generate', {
        method: 'POST',
        body: JSON.stringify({
          ca_id: currentCa?.id,
          validity_days: Number(crlDraft.validity_days),
          is_delta: crlDraft.is_delta,
          partition_index: Number(crlDraft.partition_index),
          partition_count: Number(crlDraft.partition_count),
        }),
      });
      setStatus(`CRL #${result.crl_number} 생성 완료`);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function runMaintenance() {
    try {
      const result = await api('/api/v1/maintenance/run', {
        method: 'POST',
        body: JSON.stringify({
          backup: true,
          purge_expired_certificates: true,
          purge_expired_crls: true,
          purge_metric_events: true,
          purge_audit_events: maintenanceDraft.purge_audit_events,
          optimize: true,
          generate_crls: maintenanceDraft.generate_crls,
          crl_validity_days: Number(maintenanceDraft.crl_validity_days),
          crl_partition_count: Number(maintenanceDraft.crl_partition_count),
          older_than_days: Number(maintenanceDraft.older_than_days),
          batch_size: Number(maintenanceDraft.batch_size),
        }),
      });
      setStatus(`유지보수 완료: 생성 CRL ${result.generated_crls}, 삭제 인증서 ${result.purged_certificates}, 삭제 CRL ${result.purged_crls}`);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function saveMaintenanceConfig() {
    try {
      const result = await api('/api/v1/maintenance/config', {
        method: 'PUT',
        body: JSON.stringify({
          enabled: maintenanceDraft.enabled,
          interval_seconds: Number(maintenanceDraft.interval_seconds),
          backup: maintenanceDraft.backup,
          purge_expired_certificates: maintenanceDraft.purge_expired_certificates,
          purge_expired_crls: maintenanceDraft.purge_expired_crls,
          purge_metric_events: maintenanceDraft.purge_metric_events,
          purge_audit_events: maintenanceDraft.purge_audit_events,
          optimize: maintenanceDraft.optimize,
          generate_crls: maintenanceDraft.generate_crls,
          crl_validity_days: Number(maintenanceDraft.crl_validity_days),
          crl_partition_count: Number(maintenanceDraft.crl_partition_count),
          older_than_days: Number(maintenanceDraft.older_than_days),
          batch_size: Number(maintenanceDraft.batch_size),
          metrics_enabled: maintenanceDraft.metrics_enabled,
          metrics_public: maintenanceDraft.metrics_public,
          metrics_device_limit: Number(maintenanceDraft.metrics_device_limit),
          metrics_event_retention_days: Number(maintenanceDraft.metrics_event_retention_days),
          audit_event_retention_days: Number(maintenanceDraft.audit_event_retention_days),
          log_level: maintenanceDraft.log_level,
          log_output: maintenanceDraft.log_output,
          log_retention_days: Number(maintenanceDraft.log_retention_days),
          log_retention_files: Number(maintenanceDraft.log_retention_files),
        }),
      });
      setMaintenanceConfig(result);
      setStatus(result.restart_required_fields?.length
        ? `설정 저장 완료, 재시작 필요: ${result.restart_required_fields.join(', ')}`
        : '설정 저장 완료');
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function createValidator() {
    try {
      const updating = Boolean(validatorDraft.id);
      await api(updating ? `/api/v1/validators/${validatorDraft.id}` : '/api/v1/validators', {
        method: updating ? 'PUT' : 'POST',
        body: JSON.stringify({
          name: validatorDraft.name,
          kind: validatorDraft.kind,
          config: JSON.parse(validatorDraft.config),
          enabled: validatorDraft.enabled,
        }),
      });
      setStatus(updating ? 'validator 수정 완료' : 'validator 생성 완료');
      setValidatorDraft(defaultValidatorDraft);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function createEjbcaFeature() {
    try {
      const updating = Boolean(ejbcaFeatureDraft.id);
      await api(updating ? `/api/v1/ejbca/features/${ejbcaFeatureDraft.id}` : '/api/v1/ejbca/features', {
        method: updating ? 'PUT' : 'POST',
        body: JSON.stringify({
          feature_type: ejbcaFeatureDraft.feature_type,
          name: ejbcaFeatureDraft.name,
          status: ejbcaFeatureDraft.status,
          config: JSON.parse(ejbcaFeatureDraft.config),
        }),
      });
      setStatus(updating ? 'EJBCA 기능 수정 완료' : 'EJBCA 기능 생성 완료');
      setEjbcaFeatureDraft(defaultEjbcaFeatureDraft);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function createCertificateProfile() {
    try {
      const updating = Boolean(certificateProfileDraft.id);
      await api(updating ? `/api/v1/certificate-profiles/${certificateProfileDraft.id}` : '/api/v1/certificate-profiles', {
        method: updating ? 'PUT' : 'POST',
        body: JSON.stringify({
          name: certificateProfileDraft.name,
          validity_days: Number(certificateProfileDraft.validity_days),
          allow_server_generated_key: certificateProfileDraft.allow_server_generated_key,
          require_san: certificateProfileDraft.require_san,
        }),
      });
      setStatus(updating ? 'certificate profile 수정 완료' : 'certificate profile 생성 완료');
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function createCa() {
    try {
      const updating = Boolean(caDraft.id);
      await api(updating ? `/api/v1/cas/${caDraft.id}` : '/api/v1/cas', {
        method: updating ? 'PUT' : 'POST',
        body: JSON.stringify(updating
          ? { name: caDraft.name, status: caDraft.status, make_default: caDraft.make_default }
          : { name: caDraft.name, subject_dn: caDraft.subject_dn, validity_days: Number(caDraft.validity_days) }),
      });
      setStatus(updating ? 'CA 수정 완료' : 'CA 생성 완료');
      setCaDraft(defaultCaDraft);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function importCa() {
    try {
      await api('/api/v1/cas/import', { method: 'POST', body: JSON.stringify(caImportDraft) });
      setStatus('외부 CA import 완료');
      setCaImportDraft({ ...caImportDraft, cert_pem: '', key_ref: '' });
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function renewCa(id) {
    try {
      const result = await api(`/api/v1/cas/${id}/renew`, {
        method: 'POST',
        body: JSON.stringify({ validity_days: 3650 }),
      });
      setStatus(`CA renewal 완료: ${result.name}`);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function rolloverCa(ca) {
    try {
      const suffix = new Date().toISOString().slice(0, 10).replaceAll('-', '');
      const result = await api(`/api/v1/cas/${ca.id}/rollover`, {
        method: 'POST',
        body: JSON.stringify({
          name: `${ca.name}-rollover-${suffix}`,
          subject_dn: ca.subject_dn,
          validity_days: 3650,
          make_default: true,
          disable_old: false,
        }),
      });
      setStatus(`CA rollover 완료: ${result.name}`);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function createEndEntityProfile() {
    try {
      const updating = Boolean(endEntityProfileDraft.id);
      await api(updating ? `/api/v1/end-entity-profiles/${endEntityProfileDraft.id}` : '/api/v1/end-entity-profiles', {
        method: updating ? 'PUT' : 'POST',
        body: JSON.stringify({
          name: endEntityProfileDraft.name,
          subject_regex: endEntityProfileDraft.subject_regex,
          allowed_dns_domains: endEntityProfileDraft.allowed_dns_domains.split(',').map((value) => value.trim()).filter(Boolean),
          default_certificate_profile_id: endEntityProfileDraft.default_certificate_profile_id || certificateProfiles[0]?.id || '',
        }),
      });
      setStatus(updating ? 'end entity profile 수정 완료' : 'end entity profile 생성 완료');
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function createCmpAlias() {
    try {
      const updating = Boolean(cmpAliasDraft.id);
      await api(updating ? `/api/v1/cmp-aliases/${cmpAliasDraft.id}` : '/api/v1/cmp-aliases', {
        method: updating ? 'PUT' : 'POST',
        body: JSON.stringify({
          alias: cmpAliasDraft.alias,
          ca_id: cmpAliasDraft.ca_id || currentCa?.id || '',
          certificate_profile_id: cmpAliasDraft.certificate_profile_id || certificateProfiles[0]?.id || '',
          end_entity_profile_id: cmpAliasDraft.end_entity_profile_id || endEntityProfiles[0]?.id || '',
          enabled: cmpAliasDraft.enabled,
          hmac_secret: cmpAliasDraft.hmac_secret || undefined,
          clear_hmac_secret: updating ? cmpAliasDraft.clear_hmac_secret : undefined,
        }),
      });
      setStatus(updating ? 'CMP alias 수정 완료' : 'CMP alias 생성 완료');
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function createAccessRole() {
    try {
      const updating = Boolean(accessRoleDraft.id);
      await api(updating ? `/api/v1/access-roles/${accessRoleDraft.id}` : '/api/v1/access-roles', {
        method: updating ? 'PUT' : 'POST',
        body: JSON.stringify({
          name: accessRoleDraft.name,
          permissions: accessRoleDraft.permissions.split(',').map((value) => value.trim()).filter(Boolean),
          api_token: accessRoleDraft.api_token || undefined,
          certificate_issuer_dn: accessRoleDraft.certificate_issuer_dn || undefined,
          certificate_match_key: accessRoleDraft.certificate_match_key || undefined,
          certificate_match_value: accessRoleDraft.certificate_match_value || undefined,
          clear_api_token: updating ? accessRoleDraft.clear_api_token : undefined,
          clear_certificate_member: updating ? accessRoleDraft.clear_certificate_member : undefined,
        }),
      });
      setStatus(updating ? 'access role 수정 완료' : 'access role 생성 완료');
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function createEndEntity() {
    try {
      const updating = Boolean(endEntityDraft.id);
      await api(updating ? `/api/v1/end-entities/${endEntityDraft.id}` : '/api/v1/end-entities', {
        method: updating ? 'PUT' : 'POST',
        body: JSON.stringify({
          username: endEntityDraft.username,
          subject_dn: endEntityDraft.subject_dn,
          dns_names: endEntityDraft.dns_names.split(',').map((value) => value.trim()).filter(Boolean),
          email: endEntityDraft.email || undefined,
          ca_id: endEntityDraft.ca_id || currentCa?.id || undefined,
          certificate_profile_id: endEntityDraft.certificate_profile_id || certificateProfiles[0]?.id || undefined,
          end_entity_profile_id: endEntityDraft.end_entity_profile_id || endEntityProfiles[0]?.id || undefined,
          status: endEntityDraft.status,
          password: endEntityDraft.password || undefined,
          token_type: endEntityDraft.token_type || undefined,
        }),
      });
      setStatus(updating ? 'end entity 수정 완료' : 'end entity 등록 완료');
      setEndEntityDraft(defaultEndEntityDraft);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function createApproval() {
    try {
      await api('/api/v1/approvals', {
        method: 'POST',
        body: JSON.stringify({
          action: approvalDraft.action,
          target_id: approvalDraft.target_id,
          request: JSON.parse(approvalDraft.request_json),
          expires_at: approvalDraft.expires_at ? Number(approvalDraft.expires_at) : undefined,
        }),
      });
      setStatus('approval 요청 생성 완료');
      setApprovalDraft(defaultApprovalDraft);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function decideApproval(id, decisionStatus) {
    try {
      await api(`/api/v1/approvals/${id}/decision`, {
        method: 'PUT',
        body: JSON.stringify({
          status: decisionStatus,
          decision: { decided_from: 'adminweb' },
        }),
      });
      setStatus(`approval ${decisionStatus}`);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function removeConfig(path, label) {
    try {
      await api(path, { method: 'DELETE' });
      setStatus(`${label} 삭제 완료`);
      await refreshAll();
    } catch (error) {
      setStatus(error.message);
    }
  }

  const data = {
    summary,
    cas,
    certs,
    crls,
    validators,
    maintenanceConfig,
    certificateProfiles,
    endEntityProfiles,
    cmpAliases,
    accessRoles,
    endEntities,
    approvals,
    ejbcaFeatures,
    auditEvents,
    auditChain,
  };
  const drafts = {
    issue,
    csr,
    certFilter,
    caDraft,
    caImportDraft,
    crlDraft,
    certificateProfileDraft,
    endEntityProfileDraft,
    cmpAliasDraft,
    accessRoleDraft,
    endEntityDraft,
    approvalDraft,
    ejbcaFeatureDraft,
    validatorDraft,
    maintenanceDraft,
  };
  const setters = {
    setIssue,
    setCsr,
    setCertFilter,
    setCaDraft,
    setCaImportDraft,
    setCrlDraft,
    setCertificateProfileDraft,
    setEndEntityProfileDraft,
    setCmpAliasDraft,
    setAccessRoleDraft,
    setEndEntityDraft,
    setApprovalDraft,
    setEjbcaFeatureDraft,
    setValidatorDraft,
    setMaintenanceDraft,
  };
  const actions = {
    refreshAll,
    issueGenerated,
    issueBrowserCertificate,
    issueCsr,
    revoke,
    downloadCertificate,
    generateCrl,
    runMaintenance,
    saveMaintenanceConfig,
    createValidator,
    createCertificateProfile,
    createCa,
    importCa,
    renewCa,
    rolloverCa,
    createEndEntityProfile,
    createCmpAlias,
    createAccessRole,
    createEndEntity,
    createApproval,
    decideApproval,
    createEjbcaFeature,
    removeConfig,
  };

  function handleLogout() {
    setToken('');
    localStorage.removeItem('ejbca-rs-token');
    setActivePage('dashboard');
    setStatus('저장된 API 토큰을 지웠습니다. mTLS 인증은 브라우저 인증서나 프록시 세션을 종료해야 완전히 해제됩니다.');
  }

  if (!adminAccessGranted) {
    return (
      <AdminWebEntry
        session={adminSession}
        checking={sessionChecking}
        status={status}
        onRetry={refreshAdminSession}
      />
    );
  }

  return (
    <main className="shell ejbcaShell">
      <header id="header" className="adminHeader">
        <div id="banner" className="banner">
          <button
            type="button"
            className="brandLink"
            title="홈으로 이동"
            onClick={() => setActivePage('dashboard')}
          >
            <span className="logoMark">EJBCA</span>
            <span className="brandText">
              <strong>EJBCA Administration</strong>
              <span>ejbca-rs AdminWeb</span>
            </span>
          </button>
        </div>
        <div className="tokenBox">
          <label title="mTLS 클라이언트 인증서를 통과한 뒤 API 권한을 더 좁혀야 할 때 사용하는 선택 토큰입니다.">
            API 토큰(선택)
          </label>
          <input
            value={token}
            onChange={(event) => setToken(event.target.value)}
            placeholder="x-admin-token"
            type="password"
          />
          <button title="새로고침" onClick={refreshAll}>
            <RefreshCw size={18} />
          </button>
        </div>
      </header>

      <MainNavigation
        groups={menuGroups}
        activePage={activePage}
        onChange={setActivePage}
        onLogout={handleLogout}
      />

      <section className="mainWrapper">
        <section className="container">
          <section id="messagesBlock" className="messagesBlock">
            <AdminSessionBar session={adminSession} onRetry={refreshAdminSession} />
            <div className="globalMessages infoMessage" title="마지막 작업 상태">
              {status || '준비됨'}
            </div>
          </section>
          <section id="contentBlock" className="contentBlock">
            <PageHeader page={pageMeta} onRefresh={refreshAll} />
            {activePage !== 'manual' && (
              <ContextBar cas={cas} currentCa={currentCa} onSelect={setSelectedCaId} />
            )}
            <section className="pageBody">
              <div className="pageMain">
                {activePage === 'dashboard' && <DashboardPage data={data} />}
                {activePage === 'certificates' && <CertificatesPage data={data} drafts={drafts} setters={setters} actions={actions} />}
                {activePage === 'ra' && <RaPage data={data} drafts={drafts} setters={setters} actions={actions} />}
                {activePage === 'cas' && <CaPage data={data} drafts={drafts} setters={setters} actions={actions} />}
                {activePage === 'profiles' && <ProfilesPage data={data} drafts={drafts} setters={setters} actions={actions} />}
                {activePage === 'cmp' && <CmpPage data={data} drafts={drafts} setters={setters} actions={actions} />}
                {activePage === 'roles' && <RolesPage data={data} drafts={drafts} setters={setters} actions={actions} />}
                {activePage === 'ejbca' && <EjbcaFeaturesPage data={data} drafts={drafts} setters={setters} actions={actions} />}
                {activePage === 'validators' && <ValidatorsPage data={data} drafts={drafts} setters={setters} actions={actions} />}
                {activePage === 'maintenance' && <MaintenancePage data={data} drafts={drafts} setters={setters} actions={actions} />}
                {activePage === 'audit' && <AuditPage data={data} />}
                {activePage === 'manual' && <ManualPage />}
              </div>
              <GuidancePanel pageId={activePage} onNavigate={setActivePage} />
            </section>
          </section>
        </section>
      </section>

      <footer id="footerBlock" className="footerBlock">
        <div className="footerInner">
          ejbca-rs AdminWeb - EJBCA 원본 AdminWeb 레이아웃을 기준으로 한 한국어 관리 콘솔
        </div>
      </footer>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
