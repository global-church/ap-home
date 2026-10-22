export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
import { onVerify, onRequestOptions } from '../../../../server/connect/org-contact';
import { makeEnv } from '../../../_lib/env';

export const POST = (request: Request) => onVerify({ request, env: makeEnv() });
export const OPTIONS = () => onRequestOptions();
