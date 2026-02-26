import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = dirname(fileURLToPath(import.meta.url));

export default {
  server: {
    port: 5174,
    open: false,
  },
  resolve: {
    alias: {
      '@': resolve(root, 'src'),
    },
  },
};
