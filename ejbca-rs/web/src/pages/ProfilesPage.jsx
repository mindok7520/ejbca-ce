import React from 'react';
import { ListChecks, SlidersHorizontal, Trash2 } from 'lucide-react';
import { Panel, Table } from '../components/common';
import { short } from '../lib/format';

export function ProfilesPage({ data, drafts, setters, actions }) {
  const { certificateProfiles, endEntityProfiles } = data;
  const { certificateProfileDraft, endEntityProfileDraft } = drafts;
  const { setCertificateProfileDraft, setEndEntityProfileDraft } = setters;
  const { createCertificateProfile, createEndEntityProfile, removeConfig } = actions;

  return (
    <section className="grid">
      <Panel title="Certificate profile" icon={SlidersHorizontal}>
        {certificateProfileDraft.id && <div className="maintenanceState"><span>수정 중</span><strong>cert</strong><span>{short(certificateProfileDraft.id)}</span></div>}
        <div className="inlineControls">
          <input
            value={certificateProfileDraft.name}
            onChange={(e) => setCertificateProfileDraft({ ...certificateProfileDraft, name: e.target.value })}
          />
          <input
            type="number"
            value={certificateProfileDraft.validity_days}
            onChange={(e) => setCertificateProfileDraft({ ...certificateProfileDraft, validity_days: e.target.value })}
          />
        </div>
        <div className="checkRow">
          <label>
            <input
              type="checkbox"
              checked={certificateProfileDraft.allow_server_generated_key}
              onChange={(e) => setCertificateProfileDraft({ ...certificateProfileDraft, allow_server_generated_key: e.target.checked })}
            />
            서버 키
          </label>
          <label>
            <input
              type="checkbox"
              checked={certificateProfileDraft.require_san}
              onChange={(e) => setCertificateProfileDraft({ ...certificateProfileDraft, require_san: e.target.checked })}
            />
            SAN 필수
          </label>
        </div>
        <button onClick={createCertificateProfile}>
          <SlidersHorizontal size={18} /> {certificateProfileDraft.id ? 'Certificate profile 수정' : 'Certificate profile 추가'}
        </button>
      </Panel>

      <Panel title="End entity profile" icon={ListChecks}>
        {endEntityProfileDraft.id && <div className="maintenanceState"><span>수정 중</span><strong>end</strong><span>{short(endEntityProfileDraft.id)}</span></div>}
        <label>이름</label>
        <input
          value={endEntityProfileDraft.name}
          onChange={(e) => setEndEntityProfileDraft({ ...endEntityProfileDraft, name: e.target.value })}
        />
        <label>Subject regex</label>
        <input
          value={endEntityProfileDraft.subject_regex}
          onChange={(e) => setEndEntityProfileDraft({ ...endEntityProfileDraft, subject_regex: e.target.value })}
        />
        <label>Allowed DNS domains</label>
        <input
          value={endEntityProfileDraft.allowed_dns_domains}
          onChange={(e) => setEndEntityProfileDraft({ ...endEntityProfileDraft, allowed_dns_domains: e.target.value })}
        />
        <select
          value={endEntityProfileDraft.default_certificate_profile_id}
          onChange={(e) => setEndEntityProfileDraft({ ...endEntityProfileDraft, default_certificate_profile_id: e.target.value })}
        >
          <option value="">기본 certificate profile 없음</option>
          {certificateProfiles.map((profile) => (
            <option key={profile.id} value={profile.id}>{profile.name}</option>
          ))}
        </select>
        <button onClick={createEndEntityProfile}>
          <ListChecks size={18} /> {endEntityProfileDraft.id ? 'End entity profile 수정' : 'End entity profile 추가'}
        </button>
      </Panel>

      <Panel title="Profile 목록" icon={SlidersHorizontal}>
        <Table
          columns={['구분', '이름', '상태', '']}
          rows={[
            ...certificateProfiles.map((profile) => [
              'cert',
              profile.name,
              `${profile.validity_days}d`,
              <div className="actionButtons">
                <button title="수정" onClick={() => setCertificateProfileDraft({
                  id: profile.id,
                  name: profile.name,
                  validity_days: profile.validity_days,
                  allow_server_generated_key: profile.allow_server_generated_key,
                  require_san: profile.require_san,
                })}><SlidersHorizontal size={16} /></button>
                <button title="삭제" onClick={() => removeConfig(`/api/v1/certificate-profiles/${profile.id}`, 'certificate profile')}><Trash2 size={16} /></button>
              </div>,
            ]),
            ...endEntityProfiles.map((profile) => [
              'end',
              profile.name,
              short(profile.default_certificate_profile_id),
              <div className="actionButtons">
                <button title="수정" onClick={() => setEndEntityProfileDraft({
                  id: profile.id,
                  name: profile.name,
                  subject_regex: profile.subject_regex || '',
                  allowed_dns_domains: profile.allowed_dns_domains.join(','),
                  default_certificate_profile_id: profile.default_certificate_profile_id || '',
                })}><SlidersHorizontal size={16} /></button>
                <button title="삭제" onClick={() => removeConfig(`/api/v1/end-entity-profiles/${profile.id}`, 'end entity profile')}><Trash2 size={16} /></button>
              </div>,
            ]),
          ]}
        />
      </Panel>
    </section>
  );
}
