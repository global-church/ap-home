import { describe, expect, it } from 'vitest';
import { deploymentRelyingApps } from './deployment-apps';
import { skillsRegistryOrigin } from '../lib/domain';
import type { RelyingApp } from './schema';

const app = (client_id: string, redirect_uris: string[]) => ({ client_id, name: client_id, redirect_uris, allowed_scopes: ['openid'], allowed_delegation_templates: ['site-login'] }) as unknown as RelyingApp;
const ALL = [
  app('gather-app', ['https://gather27.gccommons.app/auth', 'http://localhost:5175/auth', 'http://127.0.0.1:5175/auth']),
  app('field-app', ['https://field-web.example.dev/auth']),
  app('pokernight', ['https://poker.example.io/auth']),
];

describe('the built-in apps a deployment accepts (2026-10-27)', () => {
  it('unset keeps every app, as upstream', () => {
    expect(deploymentRelyingApps(ALL, undefined, undefined).map((a) => a.client_id)).toEqual(['gather-app', 'field-app', 'pokernight']);
  });
  it('a list keeps only the named apps; another estate’s apps cannot start a sign-in', () => {
    expect(deploymentRelyingApps(ALL, ' Gather-App ', undefined).map((a) => a.client_id)).toEqual(['gather-app']);
  });
  it('local redirects off drops localhost and 127.0.0.1 return addresses, keeps the real ones', () => {
    const [g] = deploymentRelyingApps(ALL, 'gather-app', 'off');
    expect(g!.redirect_uris).toEqual(['https://gather27.gccommons.app/auth']);
  });
});

it('redirect hosts keep only return addresses on the named domains (another estate’s defaults go)', () => {
  const apps = [app('gather-app', ['https://gather27.gccommons.app/', 'https://ops.gather27.gccommons.app/', 'https://gather27-web.other-estate.workers.dev/', 'https://groups.gather27.com/'])];
  expect(deploymentRelyingApps(apps, 'gather-app', 'off', 'gccommons.app, gather27.com')[0]!.redirect_uris)
    .toEqual(['https://gather27.gccommons.app/', 'https://ops.gather27.gccommons.app/', 'https://groups.gather27.com/']);
});

describe('the skills registry setting', () => {
  it('off means none; unset keeps the upstream default; a value is used as given', () => {
    expect(skillsRegistryOrigin('off')).toBe('');
    expect(skillsRegistryOrigin(' OFF ')).toBe('');
    expect(skillsRegistryOrigin(undefined)).toMatch(/^https:\/\//);
    expect(skillsRegistryOrigin('https://skills.example.org')).toBe('https://skills.example.org');
  });
});
