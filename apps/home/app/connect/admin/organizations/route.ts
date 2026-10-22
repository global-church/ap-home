export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
import { onAdminOrganizations } from '../../../../server/connect/admin';
import { makeEnv } from '../../../_lib/env';

export const GET = (request: Request) => onAdminOrganizations({ request, env: makeEnv() });
