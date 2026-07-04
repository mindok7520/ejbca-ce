import React from 'react';
import { BookOpen } from 'lucide-react';
import { Panel } from '../components/common';
import { manuals, operatorGuideSections, pages } from '../data/adminweb';

export function ManualPage() {
  return (
    <section className="manualGrid">
      <section className="operatorGuide">
        <header>
          <BookOpen size={20} />
          <div>
            <h2>RA mode 운영 매뉴얼</h2>
            <p>CA, 벤더 CA, 장비 인증서 정책, CMP alias, access role을 실제 운영 순서로 설정합니다.</p>
          </div>
        </header>
        <div className="operatorGuideGrid">
          {operatorGuideSections.map((section) => (
            <article key={section.title} className="operatorGuideCard">
              <h3>{section.title}</h3>
              <ul>
                {section.entries.map((entry) => <li key={entry}>{entry}</li>)}
              </ul>
            </article>
          ))}
        </div>
      </section>
      {pages.filter((page) => page.id !== 'manual').map((page) => {
        const Icon = page.icon;
        return (
          <Panel key={page.id} title={page.label} icon={Icon || BookOpen}>
            <ul className="manualList">
              {(manuals[page.id] || []).map((entry) => <li key={entry}>{entry}</li>)}
            </ul>
          </Panel>
        );
      })}
    </section>
  );
}
