// ORGANIZATION TYPE (Global.Church, 2026-10-21) — what kind of organization this is, chosen when it is created.
//
// A relying app (Gather) asks for it on the organization step: a `gc:OrganizationTypeValue` from the gc ontology
// at a tagged release, or "Other" with the person's own words, which the team reviews in Admin to find the
// categories the ontology is missing. It arrives on org-create as `org_type` (base64url JSON, like
// `registry_entry`), is written to the org's vault `org.profile` as `organizationType` (the record), and rides the
// `related:` link so Admin can count it (a projection). Home keeps no list of types: the app sends the label with
// the IRI, and this file only checks the shape.

/** The gc ontology's organization-type values all live under this IRI prefix. */
const ORG_TYPE_IRI_PREFIX = 'https://ontology.global.church/core#organizationtypevalue-';

export interface OrgTypeV1 {
  /** A `gc:OrganizationTypeValue` IRI, or null for Other. */
  iri: string | null;
  /** The label the person chose ("Church", "Mission Agency", "Other"). */
  label: string;
  /** Other only: what the person typed. */
  other?: string;
  /** The tagged ontology release the IRI is cited from. */
  ontology?: string;
}

const clean = (v: unknown, max: number): string => (typeof v === 'string' ? v.replace(/\s+/g, ' ').trim().slice(0, max) : '');

/** The checked type, or null for anything that isn't one. Used on the param AND again on the server. */
export function checkOrgType(v: unknown): OrgTypeV1 | null {
  if (!v || typeof v !== 'object') return null;
  const r = v as Record<string, unknown>;
  const label = clean(r.label, 60);
  const ontology = clean(r.ontology, 300);
  const onto = /^https:\/\//.test(ontology) ? { ontology } : {};
  if (r.iri === null || r.iri === undefined) {
    const other = clean(r.other, 80);
    return other ? { iri: null, label: label || 'Other', other, ...onto } : null;
  }
  if (typeof r.iri !== 'string' || !r.iri.startsWith(ORG_TYPE_IRI_PREFIX) || !/^[a-z]{2,8}$/.test(r.iri.slice(ORG_TYPE_IRI_PREFIX.length))) return null;
  if (!label) return null;
  return { iri: r.iri, label, ...onto };
}

/** `org_type` from the authorize URL: base64url JSON, capped. */
export function parseOrgTypeParam(param: string | null | undefined): OrgTypeV1 | null {
  if (!param || param.length > 2000) return null;
  try {
    const b64 = param.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    return checkOrgType(JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)))));
  } catch {
    return null;
  }
}

/** Back to the param, for a resumed ceremony. */
export function orgTypeParam(t: OrgTypeV1): string {
  const bytes = new TextEncoder().encode(JSON.stringify(t));
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** How a type reads on a page: "Church", or "Other: House church network". */
export function orgTypeText(t: OrgTypeV1 | null | undefined): string {
  if (!t) return '';
  return t.iri === null ? `Other: ${t.other ?? ''}` : t.label;
}
