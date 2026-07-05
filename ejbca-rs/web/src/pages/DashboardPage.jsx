import React from 'react';
import { BookOpen, Download, FileKey, Home, ScrollText, ShieldCheck, SlidersHorizontal, Trash2 } from 'lucide-react';
import { Metric, Panel, Table } from '../components/common';
import { formatTs } from '../lib/format';

export function DashboardPage({ data }) {
  const { summary, auditChain, auditEvents } = data;
  return (
    <section className="grid">
      <Panel title="운영 요약" icon={Home}>
        <section className="metrics">
          <Metric icon={ShieldCheck} label="CA" value={summary?.ca_count ?? '-'} />
          <Metric icon={FileKey} label="활성 인증서" value={summary?.active_certificates ?? '-'} />
          <Metric icon={Trash2} label="폐기 인증서" value={summary?.revoked_certificates ?? '-'} />
          <Metric icon={Download} label="CRL" value={summary?.crl_count ?? '-'} />
          <Metric
            icon={SlidersHorizontal}
            label="정책"
            value={summary ? summary.certificate_profile_count + summary.end_entity_profile_count + summary.cmp_alias_count : '-'}
          />
          <Metric icon={BookOpen} label="EJBCA 기능" value={summary?.ejbca_feature_count ?? '-'} />
        </section>
      </Panel>
      <Panel title="최근 감사 상태" icon={ScrollText}>
        <div className="maintenanceState">
          <span>Hash chain</span>
          <strong>{auditChain ? (auditChain.valid ? 'valid' : 'invalid') : '-'}</strong>
          <span>{auditChain ? `${auditChain.checked_events} checked` : '-'}</span>
        </div>
        <Table
          columns={['시간', 'Actor', 'Action', 'Status']}
          rows={auditEvents.slice(0, 8).map((event) => [
            formatTs(event.ts),
            event.actor,
            event.action,
            event.status,
          ])}
        />
      </Panel>
    </section>
  );
}
