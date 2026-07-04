import React from 'react';
import { BookOpen, LockKeyhole, RefreshCw } from 'lucide-react';
import { manuals, pages } from '../data/adminweb';

export function Metric({ icon: Icon, label, value }) {
  return (
    <div className="metric">
      <Icon size={20} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function Panel({ title, icon: Icon, children }) {
  return (
    <section className="panel">
      <h2>
        <Icon size={19} /> {title}
      </h2>
      {children}
    </section>
  );
}

export function ProviderBadge({ value }) {
  return <span className={`provider provider-${value}`}>{value}</span>;
}

export function Table({ columns, rows }) {
  return (
    <div className="tableWrap">
      <table>
        <thead>
          <tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td className="emptyCell" colSpan={columns.length}>-</td>
            </tr>
          ) : rows.map((row, index) => (
            <tr key={index}>{row.map((cell, cellIndex) => <td key={cellIndex}>{cell}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function AdminWebEntry({ session, checking, status, onRetry }) {
  return (
    <main className="entryShell">
      <section className="entryPanel">
        <LockKeyhole size={34} />
        <div>
          <h1>ejbca-rs AdminWeb</h1>
          <p>{checking ? 'AdminWeb client certificate 상태를 확인하는 중입니다.' : session?.detail || status}</p>
        </div>
        <div className="manualCard">
          <strong>접근 방식</strong>
          <span>첫 진입 화면은 공개로 보이지만, 내부 기능 페이지는 검증된 client certificate 세션이 있어야 열립니다.</span>
          <span>운영 환경에서는 mTLS 프록시가 client certificate를 검증한 뒤 `x-admin-client-cert-pem` 헤더로 백엔드에 전달하게 구성합니다.</span>
        </div>
        <button onClick={onRetry}>
          <RefreshCw size={16} /> 다시 확인
        </button>
        <footer>{status || '인증서 확인 대기'}</footer>
      </section>
    </main>
  );
}

export function SideNav({ activePage, onChange }) {
  return (
    <nav className="sideNav" aria-label="AdminWeb 기능 메뉴">
      {pages.map((page) => {
        const Icon = page.icon;
        return (
          <button
            key={page.id}
            className={activePage === page.id ? 'active' : ''}
            onClick={() => onChange(page.id)}
          >
            <Icon size={18} /> {page.label}
          </button>
        );
      })}
    </nav>
  );
}

export function PageHeader({ page, onRefresh }) {
  return (
    <div className="pageHeader">
      <div>
        <h2>{page.label}</h2>
        <p>{(manuals[page.id] || manuals.manual)[0]}</p>
      </div>
      <button title="현재 데이터 새로고침" onClick={onRefresh}>
        <RefreshCw size={16} /> 동기화
      </button>
    </div>
  );
}

export function ContextBar({ cas, currentCa, onSelect }) {
  return (
    <section className="contextBar">
      <label>운영 CA</label>
      <select value={currentCa?.id ?? ''} onChange={(e) => onSelect(e.target.value)}>
        {cas.map((ca) => (
          <option key={ca.id} value={ca.id}>
            {ca.name}{ca.is_default ? ' / default' : ''}{ca.status !== 'active' ? ' / disabled' : ''}
          </option>
        ))}
      </select>
      <ProviderBadge value={currentCa?.key_provider ?? '-'} />
      <span>{currentCa?.status ?? '-'}</span>
      <span className="monoText">{currentCa?.subject_dn ?? '-'}</span>
    </section>
  );
}

export function AdminSessionBar({ session, onRetry }) {
  return (
    <section className="adminSessionBar">
      <LockKeyhole size={18} />
      <div>
        <strong>{session?.required ? 'Client certificate required' : 'Client certificate optional'}</strong>
        <span>{session?.role_name ? `${session.role_name} · ${session.subject_dn}` : session?.subject_dn || session?.detail || 'AdminWeb certificate gate'}</span>
      </div>
      <button title="인증서 세션 다시 확인" onClick={onRetry}>
        <RefreshCw size={16} />
      </button>
    </section>
  );
}

export function ManualPanel({ pageId }) {
  const entries = manuals[pageId] || manuals.manual;
  return (
    <aside className="manualPanel">
      <h2><BookOpen size={18} /> 사용법</h2>
      <ul>
        {entries.map((entry) => <li key={entry}>{entry}</li>)}
      </ul>
    </aside>
  );
}
