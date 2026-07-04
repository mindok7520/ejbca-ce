import React from 'react';
import { ShieldCheck, SlidersHorizontal, Trash2 } from 'lucide-react';
import { Panel, Table } from '../components/common';
import { short } from '../lib/format';

export function RolesPage({ data, drafts, setters, actions }) {
  const { accessRoles } = data;
  const { accessRoleDraft } = drafts;
  const { setAccessRoleDraft } = setters;
  const { createAccessRole, removeConfig } = actions;

  return (
    <section className="grid">
      <Panel title="Access role" icon={ShieldCheck}>
        {accessRoleDraft.id && <div className="maintenanceState"><span>수정 중</span><strong>role</strong><span>{short(accessRoleDraft.id)}</span></div>}
        <label>이름</label>
        <input value={accessRoleDraft.name} onChange={(e) => setAccessRoleDraft({ ...accessRoleDraft, name: e.target.value })} />
        <label>권한</label>
        <input value={accessRoleDraft.permissions} onChange={(e) => setAccessRoleDraft({ ...accessRoleDraft, permissions: e.target.value })} />
        <label>API token</label>
        <input
          type="password"
          value={accessRoleDraft.api_token}
          onChange={(e) => setAccessRoleDraft({ ...accessRoleDraft, api_token: e.target.value })}
          placeholder="role API token"
        />
        <label>Certificate issuer DN</label>
        <input
          value={accessRoleDraft.certificate_issuer_dn}
          onChange={(e) => setAccessRoleDraft({ ...accessRoleDraft, certificate_issuer_dn: e.target.value })}
          placeholder="CN=Management CA,O=Example"
        />
        <label>Certificate match key</label>
        <select
          value={accessRoleDraft.certificate_match_key}
          onChange={(e) => setAccessRoleDraft({ ...accessRoleDraft, certificate_match_key: e.target.value })}
        >
          <option value="serial_hex">Serial number</option>
          <option value="subject_dn">Full subject DN</option>
          <option value="common_name">Common name</option>
          <option value="any">Any certificate from issuer</option>
        </select>
        {accessRoleDraft.certificate_match_key !== 'any' && (
          <>
            <label>Certificate match value</label>
            <input
              value={accessRoleDraft.certificate_match_value}
              onChange={(e) => setAccessRoleDraft({ ...accessRoleDraft, certificate_match_value: e.target.value })}
              placeholder="serial hex, subject DN, or CN"
            />
          </>
        )}
        <div className="checkRow">
          <label>
            <input
              type="checkbox"
              checked={accessRoleDraft.clear_api_token}
              onChange={(e) => setAccessRoleDraft({ ...accessRoleDraft, clear_api_token: e.target.checked })}
            />
            Token 제거
          </label>
          <label>
            <input
              type="checkbox"
              checked={accessRoleDraft.clear_certificate_member}
              onChange={(e) => setAccessRoleDraft({ ...accessRoleDraft, clear_certificate_member: e.target.checked })}
            />
            Certificate member 제거
          </label>
        </div>
        <button onClick={createAccessRole}>
          <ShieldCheck size={18} /> {accessRoleDraft.id ? 'Access role 수정' : 'Access role 추가'}
        </button>
      </Panel>

      <Panel title="Access role 목록" icon={ShieldCheck}>
        <Table
          columns={['이름', '권한', 'Token', 'Certificate member', '']}
          rows={accessRoles.map((role) => [
            role.name,
            role.permissions.join(','),
            role.api_token_configured ? 'configured' : '-',
            role.certificate_member_configured
              ? `${role.certificate_match_key}:${role.certificate_match_value || '*'}`
              : '-',
            <div className="actionButtons">
              <button title="수정" onClick={() => setAccessRoleDraft({
                id: role.id,
                name: role.name,
                permissions: role.permissions.join(','),
                api_token: '',
                certificate_issuer_dn: role.certificate_issuer_dn || '',
                certificate_match_key: role.certificate_match_key || 'serial_hex',
                certificate_match_value: role.certificate_match_value || '',
                clear_api_token: false,
                clear_certificate_member: false,
              })}><SlidersHorizontal size={16} /></button>
              <button title="삭제" onClick={() => removeConfig(`/api/v1/access-roles/${role.id}`, 'access role')}><Trash2 size={16} /></button>
            </div>,
          ])}
        />
      </Panel>
    </section>
  );
}
