import React from 'react';
import { ListChecks, SlidersHorizontal, Trash2 } from 'lucide-react';
import { Panel, Table } from '../components/common';
import { short } from '../lib/format';

export function ValidatorsPage({ data, drafts, setters, actions }) {
  const { validators } = data;
  const { validatorDraft } = drafts;
  const { setValidatorDraft } = setters;
  const { createValidator, removeConfig } = actions;

  return (
    <section className="grid">
      <Panel title="Validator" icon={ListChecks}>
        {validatorDraft.id && <div className="maintenanceState"><span>수정 중</span><strong>validator</strong><span>{short(validatorDraft.id)}</span></div>}
        <label>이름</label>
        <input
          value={validatorDraft.name}
          onChange={(e) => setValidatorDraft({ ...validatorDraft, name: e.target.value })}
        />
        <label>종류</label>
        <select
          value={validatorDraft.kind}
          onChange={(e) => setValidatorDraft({ ...validatorDraft, kind: e.target.value })}
        >
          <option value="dns_allowlist">DNS Allowlist</option>
          <option value="dns_denylist">DNS Denylist</option>
          <option value="deny_subject_keywords">Subject Keyword Deny</option>
          <option value="external_webhook">External Webhook</option>
        </select>
        <label>설정 JSON</label>
        <textarea
          rows={7}
          value={validatorDraft.config}
          onChange={(e) => setValidatorDraft({ ...validatorDraft, config: e.target.value })}
        />
        <div className="checkRow">
          <label>
            <input
              type="checkbox"
              checked={validatorDraft.enabled}
              onChange={(e) => setValidatorDraft({ ...validatorDraft, enabled: e.target.checked })}
            />
            활성화
          </label>
        </div>
        <button onClick={createValidator}>
          <ListChecks size={18} /> {validatorDraft.id ? 'Validator 수정' : 'Validator 추가'}
        </button>
      </Panel>

      <Panel title="Validator 목록" icon={ListChecks}>
        <Table
          columns={['이름', '종류', '상태', '']}
          rows={validators.map((validator) => [
            validator.name,
            validator.kind,
            validator.enabled ? 'enabled' : 'disabled',
            <div className="actionButtons">
              <button title="수정" onClick={() => setValidatorDraft({
                id: validator.id,
                name: validator.name,
                kind: validator.kind,
                config: JSON.stringify(validator.config, null, 2),
                enabled: validator.enabled,
              })}><SlidersHorizontal size={16} /></button>
              <button title="삭제" onClick={() => removeConfig(`/api/v1/validators/${validator.id}`, 'validator')}><Trash2 size={16} /></button>
            </div>,
          ])}
        />
      </Panel>
    </section>
  );
}
