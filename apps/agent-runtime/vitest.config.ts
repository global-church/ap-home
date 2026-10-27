import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      // The workflow adapter imports Cloudflare's runtime modules, which only exist inside a Worker.
      // Tests exercise the ENGINE-FREE core (harness-workflow-core.test.ts, the four spec-362 gates);
      // the adapter itself just needs to be importable wherever index.ts is pulled in.
      'cloudflare:workers': fileURLToPath(new URL('./test/stubs/cloudflare-workers.ts', import.meta.url)),
      'cloudflare:workflows': fileURLToPath(new URL('./test/stubs/cloudflare-workflows.ts', import.meta.url)),
    },
  },
});
