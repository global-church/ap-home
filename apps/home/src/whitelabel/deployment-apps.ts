// WHICH BUILT-IN APPS THIS DEPLOYMENT ACCEPTS (2026-10-27).
//
// The white-label config lists every relying app the upstream Home knows: its own demos, other estates' apps, local
// development entries. A deployment that is its own estate (Global.Church: "the operational environments should be
// totally separate", Rich) names the ones it accepts, and nothing else can start a sign-in here:
//
//   NEXT_PUBLIC_RELYING_APPS = "gather-app"     only these client ids (unset: all, as upstream)
//   NEXT_PUBLIC_LOCAL_REDIRECTS = "off"          drop http://localhost / 127.0.0.1 return addresses (unset: kept)
//   NEXT_PUBLIC_REDIRECT_HOSTS = "gccommons.app,gather27.com"   keep only return addresses on these domains (or
//                                               their subdomains): an app entry's defaults on another estate's hosts go
//
// Self-registered apps (oidc-registry.ts) are separate and unaffected: a member registers those, under their own rules.
import type { RelyingApp } from './schema';

const LOCAL = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i;

const list = (raw: string | undefined) => (raw ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const onHosts = (u: string, hosts: string[]) => {
  try { const h = new URL(u).hostname.toLowerCase(); return hosts.some((d) => h === d || h.endsWith(`.${d}`)); } catch { return false; }
};

export function deploymentRelyingApps(all: readonly RelyingApp[], allowRaw: string | undefined, localRaw: string | undefined, hostsRaw?: string): RelyingApp[] {
  const allow = list(allowRaw);
  const hosts = list(hostsRaw);
  const dropLocal = (localRaw ?? '').trim().toLowerCase() === 'off';
  return all
    .filter((a) => allow.length === 0 || allow.includes(a.client_id.toLowerCase()))
    .map((a) => (dropLocal ? { ...a, redirect_uris: a.redirect_uris.filter((u) => !LOCAL.test(u)) } : a))
    .map((a) => (hosts.length ? { ...a, redirect_uris: a.redirect_uris.filter((u) => LOCAL.test(u) || onHosts(u, hosts)) } : a));
}
