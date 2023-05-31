import babel from 'rollup-plugin-babel';
// import typescript from 'rollup-plugin-typescript2';
import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import nodePolyfills from 'rollup-plugin-node-polyfills';


export default {
  input: "index.js",
  plugins: [],
  output: [
    // {
    //   file: pkg.main,
    //   format: 'cjs'
    // },
    {
      file: "index.esm.js",
      format: 'esm',
    },
    // {
    //   file: "b.js",
    //   format: 'umd',
    //   name: 'Dry'
    // }
  ],
  plugins: [
    commonjs(),
    nodePolyfills({
      include: null,
      crypto: true
    }),
    resolve({
      browser: true
    }),
    // typescript({
    //   check: false
    // }),
    babel({
      presets: [['@babel/preset-env', {
        targets: {
          browsers: ['ie 11'],
        },
      }]],
    }),
    resolve()

  ]
}
