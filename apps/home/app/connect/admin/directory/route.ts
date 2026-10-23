export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
import { onAdminDirectory } from '../../../../server/connect/admin';
import { makeEnv } from '../../../_lib/env';

export const POST = (request: Request) => onAdminDirectory({ request, env: makeEnv() });
