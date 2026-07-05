import React from 'react';
import {
  ArrowRight,
  BookOpen,
  ChevronDown,
  HelpCircle,
  Info,
  LockKeyhole,
  RefreshCw,
} from 'lucide-react';
import {
  manuals,
  menuGroups,
  pageGuides,
  pages,
  panelDescriptions,
} from '../data/adminweb';

export function Metric({ icon: Icon, label, value }) {
  return (
    <div className="metric">
      <Icon size={20} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function Panel({ title, icon: Icon, children, description }) {
  const helpText = description || panelDescriptions[title];
  return (
    <section className="panel">
      <header className="panelHeader">
        <h2>
          <Icon size={18} /> {title}
        </h2>
        {helpText && (
          <span className="panelHelpIcon" title={helpText} aria-label={`${title} 설명`}>
            <HelpCircle size={15} />
          </span>
        )}
      </header>
      {helpText && <p className="panelHelp">{helpText}</p>}
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

export function MainNavigation({
  activePage,
  groups = menuGroups,
  onChange,
  onLogout,
}) {
  const activeGroup = groups.find((group) => (
    group.pageId === activePage || group.items?.some((item) => item.pageId === activePage)
  ));

  function isActive(group) {
    return group.id === activeGroup?.id;
  }

  function itemIsActive(group, item) {
    return group.id === activeGroup?.id && item.pageId === activePage;
  }

  function handleMenuItem(item) {
    if (item.action === 'logout') {
      onLogout?.();
      return;
    }
    if (item.pageId) {
      onChange(item.pageId);
    }
  }

  return (
    <nav id="mainNavigation" className="mainNavigation" aria-label="AdminWeb 기본 메뉴">
      <ul className="mainNavList">
        {groups.map((group) => {
          const Icon = group.icon;
          const active = isActive(group);
          if (!group.items?.length) {
            return (
              <li key={group.id} className="mainNavItem">
                <button
                  type="button"
                  className={active ? 'active' : ''}
                  title={group.tooltip}
                  onClick={() => handleMenuItem(group)}
                >
                  <Icon size={15} />
                  <span>{group.label}</span>
                </button>
              </li>
            );
          }
          return (
            <li key={group.id} className="mainNavItem mainNavGroup">
              <button
                type="button"
                className={active ? 'active' : ''}
                title={group.tooltip}
                aria-haspopup="menu"
              >
                <Icon size={15} />
                <span>{group.label}</span>
                <ChevronDown size={13} />
              </button>
              <ul className="mainNavSubmenu" role="menu" aria-label={group.label}>
                {group.items.map((item) => (
                  <li key={`${group.id}-${item.label}`} role="none">
                    <button
                      type="button"
                      role="menuitem"
                      className={itemIsActive(group, item) ? 'active' : ''}
                      title={item.tooltip}
                      onClick={() => handleMenuItem(item)}
                    >
                      <span className="navItemText">
                        <span>{item.label}</span>
                        <small>{item.tooltip}</small>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

export function PageHeader({ page, onRefresh }) {
  const guide = pageGuides[page.id] || pageGuides.manual;
  const Icon = page.icon || Info;
  return (
    <section className="pageHeader">
      <div className="pageHeaderMain">
        <span className="pageKicker">AdminWeb 기능</span>
        <h2>
          <Icon size={21} />
          {page.label}
        </h2>
        <p>{guide.summary || (manuals[page.id] || manuals.manual)[0]}</p>
      </div>
      <div className="pageHeaderAside">
        <button title="현재 데이터 새로고침" onClick={onRefresh}>
          <RefreshCw size={16} /> 동기화
        </button>
        <div className="primaryAction" title="이 화면에서 가장 먼저 확인할 일">
          <Info size={15} />
          <span>{guide.primaryAction}</span>
        </div>
      </div>
      {guide.steps?.length > 0 && (
        <ol className="workflowSteps" aria-label={`${page.label} 진행 순서`}>
          {guide.steps.map((step, index) => (
            <li key={step}>
              <span>{index + 1}</span>
              {step}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

export function ContextBar({ cas, currentCa, onSelect }) {
  return (
    <section className="contextBar">
      <div className="contextField">
        <label title="신규 발급, CRL 생성, CMP alias 기본값에 쓰이는 현재 선택 CA입니다.">운영 CA</label>
        <select value={currentCa?.id ?? ''} onChange={(e) => onSelect(e.target.value)}>
          {cas.map((ca) => (
            <option key={ca.id} value={ca.id}>
              {ca.name}{ca.is_default ? ' / default' : ''}{ca.status !== 'active' ? ' / disabled' : ''}
            </option>
          ))}
        </select>
      </div>
      <div className="contextMeta" title="선택된 CA의 key provider">
        <span>Key provider</span>
        <ProviderBadge value={currentCa?.key_provider ?? '-'} />
      </div>
      <div className="contextMeta" title="disabled CA는 신규 발급에 사용할 수 없습니다.">
        <span>상태</span>
        <strong>{currentCa?.status ?? '-'}</strong>
      </div>
      <div className="contextMeta wide" title="선택된 운영 CA의 Subject DN">
        <span>Subject DN</span>
        <strong className="monoText">{currentCa?.subject_dn ?? '-'}</strong>
      </div>
    </section>
  );
}

export function AdminSessionBar({ session, onRetry }) {
  return (
    <section className="adminSessionBar">
      <LockKeyhole size={18} />
      <div>
        <strong>{session?.required ? '클라이언트 인증서 필수' : '클라이언트 인증서 선택'}</strong>
        <span>{session?.role_name ? `${session.role_name} · ${session.subject_dn}` : session?.subject_dn || session?.detail || 'AdminWeb 인증서 게이트'}</span>
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

export function GuidancePanel({ pageId, onNavigate }) {
  const guide = pageGuides[pageId] || pageGuides.manual;
  const entries = manuals[pageId] || manuals.manual;

  return (
    <aside className="guidancePanel" aria-label="현재 화면 도움말">
      <section className="guidanceSection emphasis">
        <h2><HelpCircle size={17} /> 처음 보는 경우</h2>
        <p>{guide.primaryAction}</p>
      </section>

      {guide.steps?.length > 0 && (
        <section className="guidanceSection">
          <h3>작업 순서</h3>
          <ol className="guidanceSteps">
            {guide.steps.map((step, index) => (
              <li key={step}>
                <span>{index + 1}</span>
                {step}
              </li>
            ))}
          </ol>
        </section>
      )}

      {guide.terms?.length > 0 && (
        <section className="guidanceSection">
          <h3>용어 설명</h3>
          <dl className="termList">
            {guide.terms.map(([term, description]) => (
              <div key={term}>
                <dt>{term}</dt>
                <dd>{description}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      <section className="guidanceSection">
        <h3>주의사항</h3>
        <ul className="manualList compact">
          {entries.slice(0, 4).map((entry) => <li key={entry}>{entry}</li>)}
        </ul>
      </section>

      {guide.related?.length > 0 && (
        <section className="guidanceSection">
          <h3>관련 화면</h3>
          <div className="relatedLinks">
            {guide.related.map((item) => (
              <button
                key={`${item.pageId}-${item.label}`}
                type="button"
                title={`${item.label} 화면으로 이동`}
                onClick={() => onNavigate?.(item.pageId)}
              >
                {item.label}
                <ArrowRight size={14} />
              </button>
            ))}
          </div>
        </section>
      )}
    </aside>
  );
}
