export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
import { onAdminOrgTypes } from '../../../../server/connect/admin';
import { makeEnv } from '../../../_lib/env';

export const GET = (request: Request) => onAdminOrgTypes({ request, env: makeEnv() });
