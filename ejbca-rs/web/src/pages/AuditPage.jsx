import React from 'react';
import { ScrollText } from 'lucide-react';
import { Panel, Table } from '../components/common';
import { formatDetails, formatTs, short } from '../lib/format';

export function AuditPage({ data }) {
  const { auditChain, auditEvents } = data;
  return (
    <section className="grid">
      <Panel title="감사 로그" icon={ScrollText}>
        <div className="maintenanceState">
          <span>Hash chain</span>
          <strong>{auditChain ? (auditChain.valid ? 'valid' : 'invalid') : '-'}</strong>
          <span>{auditChain ? `${auditChain.checked_events} checked / ${auditChain.legacy_events} legacy` : '-'}</span>
        </div>
        {auditChain?.error && (
          <div className="maintenanceState">
            <span>{auditChain.error}</span>
            <strong>{short(auditChain.broken_event_id)}</strong>
            <span>{short(auditChain.latest_hash)}</span>
          </div>
        )}
        <Table
          columns={['시간', 'Actor', 'Action', 'Target', 'Status', 'Details']}
          rows={auditEvents.map((event) => [
            formatTs(event.ts),
            event.actor,
            event.action,
            short(event.target),
            event.status,
            formatDetails(event.details_json),
          ])}
        />
      </Panel>
    </section>
  );
}
