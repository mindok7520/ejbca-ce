import React from 'react';
import { CheckCircle2, ClipboardCheck, SlidersHorizontal, Trash2, XCircle } from 'lucide-react';
import { Panel, Table } from '../components/common';
import { short } from '../lib/format';

export function RaPage({ data, drafts, setters, actions }) {
  const { cas, certificateProfiles, endEntityProfiles, endEntities, approvals } = data;
  const { endEntityDraft, approvalDraft } = drafts;
  const { setEndEntityDraft, setApprovalDraft } = setters;
  const { createEndEntity, createApproval, decideApproval, removeConfig } = actions;

  return (
    <section className="grid">
      <Panel title="End entity" icon={ClipboardCheck}>
        {endEntityDraft.id && <div className="maintenanceState"><span>수정 중</span><strong>entity</strong><span>{short(endEntityDraft.id)}</span></div>}
        <div className="inlineControls">
          <input
            value={endEntityDraft.username}
            onChange={(e) => setEndEntityDraft({ ...endEntityDraft, username: e.target.value })}
            placeholder="username"
          />
          <select
            value={endEntityDraft.status}
            onChange={(e) => setEndEntityDraft({ ...endEntityDraft, status: e.target.value })}
          >
            {['NEW', 'INITIALIZED', 'INPROCESS', 'GENERATED', 'FAILED', 'REVOKED', 'HISTORICAL'].map((status) => (
              <option key={status} value={status}>{status}</option>
            ))}
          </select>
        </div>
        <label>Subject DN</label>
        <input
          value={endEntityDraft.subject_dn}
          onChange={(e) => setEndEntityDraft({ ...endEntityDraft, subject_dn: e.target.value })}
        />
        <label>DNS SAN</label>
        <input
          value={endEntityDraft.dns_names}
          onChange={(e) => setEndEntityDraft({ ...endEntityDraft, dns_names: e.target.value })}
        />
        <div className="inlineControls">
          <input
            value={endEntityDraft.email}
            onChange={(e) => setEndEntityDraft({ ...endEntityDraft, email: e.target.value })}
            placeholder="email"
          />
          <input
            type="password"
            value={endEntityDraft.password}
            onChange={(e) => setEndEntityDraft({ ...endEntityDraft, password: e.target.value })}
            placeholder="enrollment password"
          />
        </div>
        <div className="inlineControls three">
          <select value={endEntityDraft.ca_id} onChange={(e) => setEndEntityDraft({ ...endEntityDraft, ca_id: e.target.value })}>
            <option value="">현재/기본 CA</option>
            {cas.map((ca) => (
              <option key={ca.id} value={ca.id}>{ca.name}</option>
            ))}
          </select>
          <select
            value={endEntityDraft.certificate_profile_id}
            onChange={(e) => setEndEntityDraft({ ...endEntityDraft, certificate_profile_id: e.target.value })}
          >
            <option value="">기본 certificate profile</option>
            {certificateProfiles.map((profile) => (
              <option key={profile.id} value={profile.id}>{profile.name}</option>
            ))}
          </select>
          <select
            value={endEntityDraft.end_entity_profile_id}
            onChange={(e) => setEndEntityDraft({ ...endEntityDraft, end_entity_profile_id: e.target.value })}
          >
            <option value="">기본 end entity profile</option>
            {endEntityProfiles.map((profile) => (
              <option key={profile.id} value={profile.id}>{profile.name}</option>
            ))}
          </select>
        </div>
        <label>Token type</label>
        <input
          value={endEntityDraft.token_type}
          onChange={(e) => setEndEntityDraft({ ...endEntityDraft, token_type: e.target.value })}
        />
        <button onClick={createEndEntity}>
          <ClipboardCheck size={18} /> {endEntityDraft.id ? 'End entity 수정' : 'End entity 등록'}
        </button>
      </Panel>

      <Panel title="Approval request" icon={CheckCircle2}>
        <div className="inlineControls">
          <select
            value={approvalDraft.action}
            onChange={(e) => setApprovalDraft({ ...approvalDraft, action: e.target.value })}
          >
            <option value="issue">issue</option>
            <option value="revoke">revoke</option>
            <option value="edit_end_entity">edit_end_entity</option>
            <option value="change_status">change_status</option>
          </select>
          <input
            value={approvalDraft.target_id}
            onChange={(e) => setApprovalDraft({ ...approvalDraft, target_id: e.target.value })}
            placeholder="end entity ID 또는 certificate ID"
          />
        </div>
        <label>Expires at unix timestamp</label>
        <input
          type="number"
          value={approvalDraft.expires_at}
          onChange={(e) => setApprovalDraft({ ...approvalDraft, expires_at: e.target.value })}
        />
        <label>Request JSON</label>
        <textarea
          rows={7}
          value={approvalDraft.request_json}
          onChange={(e) => setApprovalDraft({ ...approvalDraft, request_json: e.target.value })}
        />
        <button onClick={createApproval}>
          <CheckCircle2 size={18} /> Approval 요청 생성
        </button>
      </Panel>

      <Panel title="End entity 목록" icon={ClipboardCheck}>
        <Table
          columns={['Username', 'Subject', '상태', 'Profile', '']}
          rows={endEntities.map((entity) => [
            <span className="monoText">{entity.username}<br />{short(entity.id)}</span>,
            <span>{entity.subject_dn}<br />{entity.dns_names.join(', ') || '-'}</span>,
            entity.status,
            <span>{short(entity.ca_id)}<br />{short(entity.certificate_profile_id)} / {short(entity.end_entity_profile_id)}</span>,
            <div className="actionButtons">
              <button title="수정" onClick={() => setEndEntityDraft({
                id: entity.id,
                username: entity.username,
                subject_dn: entity.subject_dn,
                dns_names: entity.dns_names.join(','),
                email: entity.email || '',
                ca_id: entity.ca_id || '',
                certificate_profile_id: entity.certificate_profile_id || '',
                end_entity_profile_id: entity.end_entity_profile_id || '',
                status: entity.status,
                password: '',
                token_type: entity.token_type || 'USERGENERATED',
              })}><SlidersHorizontal size={16} /></button>
              <button title="삭제" onClick={() => removeConfig(`/api/v1/end-entities/${entity.id}`, 'end entity')}><Trash2 size={16} /></button>
            </div>,
          ])}
        />
      </Panel>

      <Panel title="Approval 목록" icon={CheckCircle2}>
        <Table
          columns={['Action', 'Target', '상태', '요청자', '']}
          rows={approvals.map((approval) => [
            approval.action,
            <span className="monoText">{short(approval.target_id)}<br />{short(approval.id)}</span>,
            approval.status,
            approval.requester,
            <div className="actionButtons">
              <button title="승인" onClick={() => decideApproval(approval.id, 'approved')}><CheckCircle2 size={16} /></button>
              <button title="반려" onClick={() => decideApproval(approval.id, 'rejected')}><XCircle size={16} /></button>
              <button title="취소" onClick={() => decideApproval(approval.id, 'cancelled')}><Trash2 size={16} /></button>
            </div>,
          ])}
        />
      </Panel>
    </section>
  );
}
