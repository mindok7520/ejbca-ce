import React from 'react';
import { Download, FileKey, KeyRound, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
import { Panel } from '../components/common';

export function CertificatesPage({ data, drafts, setters, actions }) {
  const { cas, certs } = data;
  const { issue, csr, certFilter } = drafts;
  const { setIssue, setCsr, setCertFilter } = setters;
  const { issueGenerated, issueBrowserCertificate, issueCsr, refreshAll, downloadCertificate, revoke } = actions;

  return (
    <section className="grid">
      <Panel title="인증서 발급" icon={FileKey}>
        <label>Subject DN</label>
        <input value={issue.subject_dn} onChange={(e) => setIssue({ ...issue, subject_dn: e.target.value })} />
        <label>DNS SAN</label>
        <input value={issue.dns_names} onChange={(e) => setIssue({ ...issue, dns_names: e.target.value })} />
        <label>유효 기간</label>
        <input
          type="number"
          value={issue.validity_days}
          onChange={(e) => setIssue({ ...issue, validity_days: e.target.value })}
        />
        <button className="primary" onClick={issueGenerated}>
          <FileKey size={18} /> 서버 키 생성 발급
        </button>
        <label>PKCS#12 friendly name</label>
        <input value={issue.friendly_name} onChange={(e) => setIssue({ ...issue, friendly_name: e.target.value })} />
        <label>PKCS#12 password</label>
        <input
          type="password"
          value={issue.pkcs12_password}
          onChange={(e) => setIssue({ ...issue, pkcs12_password: e.target.value })}
        />
        <button onClick={issueBrowserCertificate}>
          <KeyRound size={18} /> 브라우저 인증서 .p12 다운로드
        </button>
        <label>CSR PEM</label>
        <textarea value={csr} onChange={(e) => setCsr(e.target.value)} rows={7} />
        <button onClick={issueCsr}>
          <ShieldCheck size={18} /> CSR 발급
        </button>
      </Panel>

      <Panel title="인증서 목록" icon={ShieldCheck}>
        <div className="filterGrid">
          <select
            value={certFilter.ca_id}
            onChange={(e) => setCertFilter({ ...certFilter, ca_id: e.target.value })}
          >
            <option value="">전체 CA</option>
            {cas.map((ca) => (
              <option key={ca.id} value={ca.id}>{ca.name}</option>
            ))}
          </select>
          <select
            value={certFilter.status}
            onChange={(e) => setCertFilter({ ...certFilter, status: e.target.value })}
          >
            <option value="">전체 상태</option>
            <option value="active">active</option>
            <option value="revoked">revoked</option>
          </select>
          <input
            value={certFilter.subject}
            onChange={(e) => setCertFilter({ ...certFilter, subject: e.target.value })}
            placeholder="Subject 포함"
          />
          <input
            value={certFilter.serial_hex}
            onChange={(e) => setCertFilter({ ...certFilter, serial_hex: e.target.value })}
            placeholder="Serial"
          />
          <input
            type="number"
            min="1"
            value={certFilter.limit}
            onChange={(e) => setCertFilter({ ...certFilter, limit: e.target.value })}
          />
          <button title="검색" onClick={refreshAll}>
            <RefreshCw size={16} />
          </button>
        </div>
        <div className="certList">
          {certs.map((cert) => (
            <article className="rowItem" key={cert.id}>
              <div>
                <strong>{cert.subject_dn}</strong>
                <span>{cert.serial_hex}</span>
              </div>
              <span className={`badge ${cert.status}`}>{cert.status}</span>
              <button title="PEM 다운로드" onClick={() => downloadCertificate(cert.id, 'pem')}>
                <Download size={16} />
              </button>
              {cert.status !== 'revoked' && (
                <button title="폐기" onClick={() => revoke(cert.id)}>
                  <Trash2 size={16} />
                </button>
              )}
            </article>
          ))}
        </div>
      </Panel>
    </section>
  );
}
