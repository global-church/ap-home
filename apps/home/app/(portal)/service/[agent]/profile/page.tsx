'use client';
// Settings → Identity & presence → Profile, for a service-class agent: the profile record in the
// AGENT's own vault, edited over its stewardship delegation. Same surface an organization gets — a
// profile belongs to the agent, and a workspace is one (ADR-0046). Co-managers too (2026-10-26): a workspace such
// as the GCID operations workspace is stewarded by people, and adding one is the same offer an org uses.
import { use } from 'react';
import { OrgProfileSection } from '../../../../../src/components/portal/settings/org-manage';
import { CoManagers } from '../../../../../src/components/portal/CoManagers';
import { useSession } from '../../../../../src/context/session';

export default function ServiceProfilePage({ params }: { params: Promise<{ agent: string }> }) {
  const { agent } = use(params);
  const { session } = useSession();
  return (
    <>
      <OrgProfileSection orgSa={agent} />
      {/* Only someone who manages this agent can load or offer (the server checks stewardship). */}
      {session && <CoManagers org={agent} session={session} />}
    </>
  );
}
