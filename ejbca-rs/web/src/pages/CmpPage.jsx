import React from 'react';
import { ShieldCheck, SlidersHorizontal, Trash2 } from 'lucide-react';
import { Panel, Table } from '../components/common';
import { short } from '../lib/format';

export function CmpPage({ data, drafts, setters, actions }) {
  const { cas, certificateProfiles, endEntityProfiles, cmpAliases } = data;
  const { cmpAliasDraft } = drafts;
  const { setCmpAliasDraft } = setters;
  const { createCmpAlias, removeConfig } = actions;

  return (
    <section className="grid">
      <Panel title="CMP alias" icon={ShieldCheck}>
        {cmpAliasDraft.id && <div className="maintenanceState"><span>수정 중</span><strong>cmp</strong><span>{short(cmpAliasDraft.id)}</span></div>}
        <div className="inlineControls">
          <input value={cmpAliasDraft.alias} onChange={(e) => setCmpAliasDraft({ ...cmpAliasDraft, alias: e.target.value })} />
          <input
            type="password"
            value={cmpAliasDraft.hmac_secret}
            onChange={(e) => setCmpAliasDraft({ ...cmpAliasDraft, hmac_secret: e.target.value })}
            placeholder="HMAC secret"
          />
        </div>
        <div className="inlineControls three">
          <select value={cmpAliasDraft.ca_id} onChange={(e) => setCmpAliasDraft({ ...cmpAliasDraft, ca_id: e.target.value })}>
            <option value="">현재 CA</option>
            {cas.map((ca) => (
              <option key={ca.id} value={ca.id}>{ca.name}</option>
            ))}
          </select>
          <select value={cmpAliasDraft.certificate_profile_id} onChange={(e) => setCmpAliasDraft({ ...cmpAliasDraft, certificate_profile_id: e.target.value })}>
            <option value="">첫 certificate profile</option>
            {certificateProfiles.map((profile) => (
              <option key={profile.id} value={profile.id}>{profile.name}</option>
            ))}
          </select>
          <select value={cmpAliasDraft.end_entity_profile_id} onChange={(e) => setCmpAliasDraft({ ...cmpAliasDraft, end_entity_profile_id: e.target.value })}>
            <option value="">첫 end entity profile</option>
            {endEntityProfiles.map((profile) => (
              <option key={profile.id} value={profile.id}>{profile.name}</option>
            ))}
          </select>
        </div>
        <div className="checkRow">
          <label>
            <input
              type="checkbox"
              checked={cmpAliasDraft.enabled}
              onChange={(e) => setCmpAliasDraft({ ...cmpAliasDraft, enabled: e.target.checked })}
            />
            활성화
          </label>
          <label>
            <input
              type="checkbox"
              checked={cmpAliasDraft.clear_hmac_secret}
              onChange={(e) => setCmpAliasDraft({ ...cmpAliasDraft, clear_hmac_secret: e.target.checked })}
            />
            HMAC 제거
          </label>
        </div>
        <button onClick={createCmpAlias}>
          <ShieldCheck size={18} /> {cmpAliasDraft.id ? 'CMP alias 수정' : 'CMP alias 추가'}
        </button>
      </Panel>

      <Panel title="CMP alias 목록" icon={ShieldCheck}>
        <Table
          columns={['Alias', 'CA', '상태', 'HMAC', '']}
          rows={cmpAliases.map((alias) => [
            alias.alias,
            short(alias.ca_id),
            alias.enabled ? 'enabled' : 'disabled',
            alias.hmac_secret_configured ? 'configured' : '-',
            <div className="actionButtons">
              <button title="수정" onClick={() => setCmpAliasDraft({
                id: alias.id,
                alias: alias.alias,
                ca_id: alias.ca_id || '',
                certificate_profile_id: alias.certificate_profile_id || '',
                end_entity_profile_id: alias.end_entity_profile_id || '',
                enabled: alias.enabled,
                hmac_secret: '',
                clear_hmac_secret: false,
              })}><SlidersHorizontal size={16} /></button>
              <button title="삭제" onClick={() => removeConfig(`/api/v1/cmp-aliases/${alias.id}`, 'CMP alias')}><Trash2 size={16} /></button>
            </div>,
          ])}
        />
      </Panel>
    </section>
  );
}
