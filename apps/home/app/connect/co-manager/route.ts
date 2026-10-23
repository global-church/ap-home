export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
import { onCoManagerGet, onCoManagerPost } from '../../../server/connect/co-manager';
import { makeEnv } from '../../_lib/env';

export const GET = (request: Request) => onCoManagerGet({ request, env: makeEnv() });
export const POST = (request: Request) => onCoManagerPost({ request, env: makeEnv() });
