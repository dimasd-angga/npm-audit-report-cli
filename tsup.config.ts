import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts', cli: 'src/cli.ts' },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  minify: false,
  target: 'node18',
  banner: ({ format }) => {
    return format === 'esm' || format === 'cjs'
      ? { js: '' }
      : { js: '' };
  },
});
