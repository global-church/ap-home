export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
import { onAdminContact } from '../../../../server/connect/admin';
import { makeEnv } from '../../../_lib/env';

export const GET = (request: Request) => onAdminContact({ request, env: makeEnv() });
