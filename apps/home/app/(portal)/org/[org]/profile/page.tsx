'use client';
import { use } from 'react';
import { OrgProfileSection } from '../../../../../src/components/portal/settings/org-manage';
import { CoManagers } from '../../../../../src/components/portal/CoManagers';
import { useSession } from '../../../../../src/context/session';
export default function OrgProfilePage({ params }: { params: Promise<{ org: string }> }) {
  const { org } = use(params);
  const { session } = useSession();
  return (
    <>
      <OrgProfileSection orgSa={org} />
      {/* Co-managers: only someone who manages this org can load or offer (the server checks stewardship). */}
      {session && <CoManagers org={org} session={session} />}
    </>
  );
}
