import React from 'react';
import { FileKey, ShieldCheck, SlidersHorizontal } from 'lucide-react';
import { Panel, ProviderBadge, Table } from '../components/common';
import { formatTs } from '../lib/format';

export function CaPage({ data, drafts, setters, actions }) {
  const { cas } = data;
  const { caDraft, caImportDraft } = drafts;
  const { setCaDraft, setCaImportDraft } = setters;
  const { createCa, importCa } = actions;

  return (
    <section className="grid">
      <Panel title="Certificate Authority" icon={ShieldCheck}>
        {caDraft.id && <div className="maintenanceState"><span>수정 중</span><strong>CA</strong><span>{caDraft.id.slice(0, 8)}...</span></div>}
        <label>이름</label>
        <input value={caDraft.name} onChange={(e) => setCaDraft({ ...caDraft, name: e.target.value })} />
        <label>Subject DN</label>
        <input
          value={caDraft.subject_dn}
          disabled={Boolean(caDraft.id)}
          onChange={(e) => setCaDraft({ ...caDraft, subject_dn: e.target.value })}
        />
        <div className="inlineControls">
          <input
            type="number"
            value={caDraft.validity_days}
            disabled={Boolean(caDraft.id)}
            onChange={(e) => setCaDraft({ ...caDraft, validity_days: e.target.value })}
          />
          <button onClick={createCa}>
            <ShieldCheck size={18} /> {caDraft.id ? 'CA 수정' : 'CA 추가'}
          </button>
        </div>
        {caDraft.id && (
          <>
            <label>상태</label>
            <select value={caDraft.status} onChange={(e) => setCaDraft({ ...caDraft, status: e.target.value })}>
              <option value="active">active</option>
              <option value="disabled">disabled</option>
            </select>
            <div className="checkRow">
              <label>
                <input
                  type="checkbox"
                  checked={caDraft.make_default}
                  onChange={(e) => setCaDraft({ ...caDraft, make_default: e.target.checked })}
                />
                기본 CA로 지정
              </label>
            </div>
          </>
        )}
      </Panel>

      <Panel title="External CA import" icon={FileKey}>
        <label>이름</label>
        <input
          value={caImportDraft.name}
          onChange={(e) => setCaImportDraft({ ...caImportDraft, name: e.target.value })}
        />
        <label>CA certificate PEM</label>
        <textarea
          rows={6}
          value={caImportDraft.cert_pem}
          onChange={(e) => setCaImportDraft({ ...caImportDraft, cert_pem: e.target.value })}
          placeholder="CA certificate PEM"
        />
        <label>Key reference</label>
        <input
          value={caImportDraft.key_ref}
          onChange={(e) => setCaImportDraft({ ...caImportDraft, key_ref: e.target.value })}
          placeholder="command:..."
        />
        <button onClick={importCa}>
          <FileKey size={18} /> External CA import
        </button>
      </Panel>

      <Panel title="CA 목록" icon={ShieldCheck}>
        <Table
          columns={['CA', '상태', 'Subject', 'Key', '만료', '']}
          rows={cas.map((ca) => [
            `${ca.name}${ca.is_default ? ' / default' : ''}`,
            ca.status,
            ca.subject_dn,
            <ProviderBadge value={ca.key_provider ?? 'database'} />,
            formatTs(ca.not_after),
            <div className="actionButtons">
              <button title="수정" onClick={() => setCaDraft({
                id: ca.id,
                name: ca.name,
                subject_dn: ca.subject_dn,
                validity_days: '',
                status: ca.status,
                make_default: false,
              })}><SlidersHorizontal size={16} /></button>
            </div>,
          ])}
        />
      </Panel>
    </section>
  );
}
