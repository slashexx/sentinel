const esbuild = require('esbuild');

const production = process.argv.includes('--production');
const watchMode = process.argv.includes('--watch');

const buildOptions = {
    entryPoints: ['./src/extension.ts'],
    bundle: true,
    outfile: 'out/extension.js',
    external: ['vscode'],
    format: 'cjs',
    platform: 'node',
    sourcemap: !production,
    minify: production,
};

if (watchMode) {
    esbuild.context(buildOptions).then(context => {
        context.watch();
    });
} else {
    esbuild.build(buildOptions);
}
