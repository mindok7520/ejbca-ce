import React from 'react';
import { BookOpen, SlidersHorizontal, Trash2 } from 'lucide-react';
import { Panel } from '../components/common';
import { short } from '../lib/format';

const featureTypes = [
  'product_scope',
  'ca_lifecycle',
  'crypto_token',
  'key_binding',
  'enrollment_protocol',
  'cmp_auth_module',
  'cmp_flow',
  'end_entity_lifecycle',
  'access_rule',
  'approval',
  'publisher',
  'db_protection',
  'cluster_node',
  'adminweb_extension',
];

const statuses = ['active', 'configured', 'disabled', 'pending', 'approved', 'rejected', 'failed'];

export function EjbcaFeaturesPage({ data, drafts, setters, actions }) {
  const { ejbcaFeatures } = data;
  const { ejbcaFeatureDraft } = drafts;
  const { setEjbcaFeatureDraft } = setters;
  const { createEjbcaFeature, removeConfig } = actions;

  return (
    <section className="grid">
      <Panel title="EJBCA 기능 객체" icon={BookOpen}>
        {ejbcaFeatureDraft.id && <div className="maintenanceState"><span>수정 중</span><strong>feature</strong><span>{short(ejbcaFeatureDraft.id)}</span></div>}
        <label>기능 타입</label>
        <select
          value={ejbcaFeatureDraft.feature_type}
          onChange={(e) => setEjbcaFeatureDraft({ ...ejbcaFeatureDraft, feature_type: e.target.value })}
        >
          {featureTypes.map((featureType) => <option key={featureType} value={featureType}>{featureType}</option>)}
        </select>
        <label>이름</label>
        <input
          value={ejbcaFeatureDraft.name}
          onChange={(e) => setEjbcaFeatureDraft({ ...ejbcaFeatureDraft, name: e.target.value })}
        />
        <label>상태</label>
        <select
          value={ejbcaFeatureDraft.status}
          onChange={(e) => setEjbcaFeatureDraft({ ...ejbcaFeatureDraft, status: e.target.value })}
        >
          {statuses.map((status) => <option key={status} value={status}>{status}</option>)}
        </select>
        <label>설정 JSON</label>
        <textarea
          rows={10}
          value={ejbcaFeatureDraft.config}
          onChange={(e) => setEjbcaFeatureDraft({ ...ejbcaFeatureDraft, config: e.target.value })}
        />
        <button onClick={createEjbcaFeature}>
          <BookOpen size={18} /> {ejbcaFeatureDraft.id ? '기능 수정' : '기능 추가'}
        </button>
      </Panel>

      <Panel title="EJBCA 기능 목록" icon={BookOpen}>
        <div className="featureList">
          {ejbcaFeatures.length === 0 ? (
            <div className="emptyCell">-</div>
          ) : ejbcaFeatures.map((feature) => (
            <article key={feature.id} className="featureItem">
              <header className="featureHeader">
                <div>
                  <strong>{feature.name}</strong>
                  <span>{feature.feature_type}</span>
                </div>
                <div className="actionButtons">
                  <button title="수정" onClick={() => setEjbcaFeatureDraft({
                    id: feature.id,
                    feature_type: feature.feature_type,
                    name: feature.name,
                    status: feature.status,
                    config: JSON.stringify(feature.config, null, 2),
                  })}><SlidersHorizontal size={16} /></button>
                  <button title="삭제" onClick={() => removeConfig(`/api/v1/ejbca/features/${feature.id}`, 'EJBCA 기능')}><Trash2 size={16} /></button>
                </div>
              </header>
              <div className="featureMeta">
                <span>{feature.status}</span>
                <span>{short(feature.id)}</span>
              </div>
              <pre className="featureConfig">{JSON.stringify(feature.config, null, 2)}</pre>
            </article>
          ))}
        </div>
      </Panel>
    </section>
  );
}
