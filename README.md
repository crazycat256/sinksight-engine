# SinkSight Engine

SinkSight Engine captures JavaScript from an existing Chromium session through
the Chrome DevTools Protocol, analyzes it for DOM XSS inputs and sinks, and
writes stable artifacts that an agent can read without speaking CDP.

## Workspace

- `sinksight-analysis` contains the platform-independent detection algorithm.
- `sinksight-collector` contains CDP collection, persistence, and exports.
- `sinksight-cli` produces the `sinksight` executable that combines both.

Keeping these components in one workspace gives the analysis library a stable
boundary for native and future WebAssembly consumers without coupling the
collector to Pamphagos.

## Commands

`collect` is the normal command. It performs collection, analysis, library
detection, persistence, and export continuously:

```text
sinksight collect \
  --devtools-active-port /path/to/DevToolsActivePort \
  --output /work/sinksight \
  --library-db /path/to/libraries.slhdb
```

Dynamic mode is the default. It uses the Debugger domain to retrieve the exact
source of executed scripts, including dynamically generated code, without
injecting objects into the page. It also collects network scripts. The engine
disables debugger pauses so a `debugger` statement cannot stop the browser.

`--mode stealth` avoids the Debugger domain. It collects network scripts and
the inline scripts and handlers present in the initial DOM. This is less
complete, but useful when minimizing observable debugger side effects matters.

Source retrieval failures are grouped by CDP method and error code. The first
ten failures in each group are printed, followed by a summary when Chromium
disconnects. Pass `--verbose-source-errors` to print every failure.

`analyze` is a manual utility and is not required after `collect`:

```text
sinksight analyze file.js --library-db /path/to/libraries.slhdb
```

## Output

- `variants/<structural-hash>/<sha256>.js`: every distinct JavaScript capture,
  stored verbatim and grouped by structural family. Sources that could not be
  structurally hashed are stored under `variants/unstructured/`.
- `export/findings.csv`: compact list intended for quick agent inspection.
- `export/findings.json`: the same findings as structured data.
- `export/origins.json`: mapping from saved scripts to pages that loaded them.
- `export/scripts.json`: script metadata and detected library versions.
- `metadata.db`: durable deduplication and observation state.

Exports are replaced atomically. An agent can therefore read them while the
collector is running. Exact SHA-256 matches avoid repeated analysis. The first
stored capture in each structural family remains its exported representative, while
the database and `variants/` retain every exact source, observation, analysis
result, and finding. Variant findings are not included in the exports.
`export/scripts.json` reports the number of variants, variants whose normalized
findings differ from the representative, and variant analysis errors.

## Pamphagos integration contract

Pamphagos only needs to start this binary next to the browser, point it at the
browser profile's `DevToolsActivePort`, and expose the output directory in the
agent workspace. SinkSight does not own Chromium and does not add an HTTP
service or an operator UI.

## WebAssembly

`crates/wasm` exposes the analysis library to JavaScript. Pushes to `main`
publish a prebuilt package on the `wasm-package` branch:

```bash
npm install github:crazycat256/sinksight-engine#wasm-package
```

```js
import init, { Engine } from "@sinksight/engine";

await init();
const engine = new Engine(libraryDbBytes);
const result = engine.analyze(source);
```

Build it locally with Rust and [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/):

```bash
npm run build
```

## License

This project is licensed under the GNU General Public License v3.0 or later.
See [LICENSE](LICENSE) for the full terms.
