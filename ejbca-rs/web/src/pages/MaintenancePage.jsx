import React from 'react';
import { Database, Download, SlidersHorizontal } from 'lucide-react';
import { Panel, Table } from '../components/common';
import { formatTs } from '../lib/format';

export function MaintenancePage({ data, drafts, setters, actions }) {
  const { maintenanceConfig, crls } = data;
  const { maintenanceDraft, crlDraft } = drafts;
  const { setMaintenanceDraft, setCrlDraft } = setters;
  const { saveMaintenanceConfig, generateCrl, runMaintenance } = actions;

  return (
    <section className="grid">
      <Panel title="운영 설정" icon={Database}>
        <div className="maintenanceState">
          <span>자동 유지보수</span>
          <strong>{maintenanceConfig?.enabled ? 'enabled' : 'disabled'}</strong>
          <span>{maintenanceConfig ? `${maintenanceConfig.interval_seconds}s` : '-'}</span>
        </div>
        <div className="maintenanceState">
          <span>로그</span>
          <strong>{maintenanceConfig?.log_output ?? '-'}</strong>
          <span>{maintenanceConfig?.log_level ?? '-'}</span>
        </div>
        <div className="maintenanceState">
          <span>Metrics</span>
          <strong>{maintenanceConfig?.metrics_enabled ? 'enabled' : 'disabled'}</strong>
          <span>{maintenanceConfig?.metrics_public ? 'public' : 'token'}</span>
        </div>
        {maintenanceConfig?.restart_required_fields?.length > 0 && (
          <div className="maintenanceState">
            <span>Restart</span>
            <strong>required</strong>
            <span>{maintenanceConfig.restart_required_fields.join(', ')}</span>
          </div>
        )}
        <div className="checkRow">
          {[
            ['enabled', '자동 유지보수'],
            ['backup', '백업'],
            ['purge_expired_certificates', '인증서 삭제'],
            ['purge_expired_crls', 'CRL 삭제'],
            ['generate_crls', 'CRL 자동 생성'],
            ['optimize', '최적화'],
          ].map(([key, label]) => (
            <label key={key}>
              <input
                type="checkbox"
                checked={maintenanceDraft[key]}
                onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, [key]: e.target.checked })}
              />
              {label}
            </label>
          ))}
        </div>
        <div className="inlineControls three">
          <input type="number" value={maintenanceDraft.interval_seconds} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, interval_seconds: e.target.value })} />
          <input type="number" value={maintenanceDraft.older_than_days} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, older_than_days: e.target.value })} />
          <input type="number" value={maintenanceDraft.batch_size} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, batch_size: e.target.value })} />
        </div>
        <div className="inlineControls three">
          <select value={maintenanceDraft.log_level} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, log_level: e.target.value })}>
            <option value="trace">trace</option>
            <option value="debug">debug</option>
            <option value="info">info</option>
            <option value="warn">warn</option>
            <option value="error">error</option>
          </select>
          <select value={maintenanceDraft.log_output} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, log_output: e.target.value })}>
            <option value="stdout">stdout</option>
            <option value="file">file</option>
            <option value="both">both</option>
          </select>
          <input type="number" value={maintenanceDraft.log_retention_days} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, log_retention_days: e.target.value })} />
        </div>
        <div className="inlineControls three">
          <input type="number" value={maintenanceDraft.metrics_device_limit} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, metrics_device_limit: e.target.value })} />
          <input type="number" value={maintenanceDraft.metrics_event_retention_days} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, metrics_event_retention_days: e.target.value })} />
          <input type="number" value={maintenanceDraft.audit_event_retention_days} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, audit_event_retention_days: e.target.value })} />
        </div>
        <div className="checkRow">
          <label><input type="checkbox" checked={maintenanceDraft.metrics_enabled} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, metrics_enabled: e.target.checked })} />Metrics</label>
          <label><input type="checkbox" checked={maintenanceDraft.metrics_public} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, metrics_public: e.target.checked })} />Public metrics</label>
          <label><input type="checkbox" checked={maintenanceDraft.purge_audit_events} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, purge_audit_events: e.target.checked })} />Audit purge</label>
        </div>
        <div className="inlineControls">
          <input type="number" value={maintenanceDraft.log_retention_files} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, log_retention_files: e.target.value })} />
          <button onClick={saveMaintenanceConfig}>
            <SlidersHorizontal size={18} /> 설정 저장
          </button>
        </div>
      </Panel>

      <Panel title="CRL 및 수동 유지보수" icon={Download}>
        <div className="inlineControls">
          <input type="number" value={maintenanceDraft.crl_validity_days} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, crl_validity_days: e.target.value })} />
          <input type="number" value={maintenanceDraft.crl_partition_count} onChange={(e) => setMaintenanceDraft({ ...maintenanceDraft, crl_partition_count: e.target.value })} />
        </div>
        <div className="inlineControls three">
          <input type="number" value={crlDraft.validity_days} onChange={(e) => setCrlDraft({ ...crlDraft, validity_days: e.target.value })} />
          <input type="number" value={crlDraft.partition_index} onChange={(e) => setCrlDraft({ ...crlDraft, partition_index: e.target.value })} />
          <input type="number" value={crlDraft.partition_count} onChange={(e) => setCrlDraft({ ...crlDraft, partition_count: e.target.value })} />
        </div>
        <div className="checkRow">
          <label><input type="checkbox" checked={crlDraft.is_delta} onChange={(e) => setCrlDraft({ ...crlDraft, is_delta: e.target.checked })} />Delta CRL</label>
        </div>
        <button className="primary" onClick={generateCrl}>
          <Download size={18} /> CRL 생성
        </button>
        <button onClick={runMaintenance}>
          <Database size={18} /> 백업/삭제/최적화
        </button>
        <Table
          columns={['번호', '종류', 'Partition', '폐기 수', '다음 갱신']}
          rows={crls.map((crl) => [
            crl.crl_number,
            crl.is_delta ? 'delta' : 'base',
            crl.partition_index,
            crl.revoked_count,
            formatTs(crl.next_update),
          ])}
        />
      </Panel>
    </section>
  );
}
