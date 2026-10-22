import { describe, expect, it } from 'vitest';

import { checkOrgDisplayName, checkOrgType, orgTypeParam, orgTypeText, parseOrgTypeParam } from './org-type';

const CHURCH = { iri: 'https://ontology.global.church/core#organizationtypevalue-chr', label: 'Church', ontology: 'https://github.com/global-church/gather27/blob/ontology-gc-2026-08-24/ontology/faith.data.ttl' };

describe('organization type (2026-10-21)', () => {
  it('round-trips through the org_type param', () => {
    expect(parseOrgTypeParam(orgTypeParam(CHURCH))).toEqual(CHURCH);
    const other = { iri: null, label: 'Other', other: 'Réseau d’églises', ontology: CHURCH.ontology };
    expect(parseOrgTypeParam(orgTypeParam(other))).toEqual(other);
  });

  it('accepts only gc organization-type IRIs', () => {
    expect(checkOrgType({ ...CHURCH, iri: 'https://example.org/core#organizationtypevalue-chr' })).toBeNull();
    expect(checkOrgType({ ...CHURCH, iri: 'https://ontology.global.church/core#denominationvalue-x' })).toBeNull();
    expect(checkOrgType({ ...CHURCH, label: '' })).toBeNull();
  });

  it('Other needs words, which are tidied and capped', () => {
    expect(checkOrgType({ iri: null, label: 'Other', other: '   ' })).toBeNull();
    expect(checkOrgType({ iri: null, label: 'Other', other: '  House   church  ' })?.other).toBe('House church');
    expect(checkOrgType({ iri: null, other: 'x'.repeat(200) })?.other).toHaveLength(80);
  });

  it('refuses junk and drops a non-https ontology link', () => {
    expect(parseOrgTypeParam('not base64 json')).toBeNull();
    expect(parseOrgTypeParam(undefined)).toBeNull();
    expect(checkOrgType({ ...CHURCH, ontology: 'javascript:alert(1)' })).toEqual({ iri: CHURCH.iri, label: 'Church' });
  });

  it('reads as the label, or Other with the words', () => {
    expect(orgTypeText(CHURCH)).toBe('Church');
    expect(orgTypeText({ iri: null, label: 'Other', other: 'House church network' })).toBe('Other: House church network');
    expect(orgTypeText(null)).toBe('');
  });
});

describe('the display name an app sends with a new organization (2026-10-22)', () => {
  it('keeps the words, tidied and capped; nothing is not a name', () => {
    expect(checkOrgDisplayName('  Richmond   Gather ')).toBe('Richmond Gather');
    expect(checkOrgDisplayName('Grace\u0007 Church')).toBe('Grace Church');
    expect(checkOrgDisplayName('x'.repeat(150))?.length).toBe(100);
    expect(checkOrgDisplayName('   ')).toBeNull();
    expect(checkOrgDisplayName(42)).toBeNull();
  });
});
