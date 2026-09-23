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

`analyze` is a manual utility and is not required after `collect`:

```text
sinksight analyze file.js --library-db /path/to/libraries.slhdb
```

## Output

- `scripts/`: captured JavaScript, stored verbatim, sharded by content hash.
- `export/findings.csv`: compact list intended for quick agent inspection.
- `export/findings.json`: the same findings as structured data.
- `export/origins.json`: mapping from saved scripts to pages that loaded them.
- `export/scripts.json`: script metadata and detected library versions.
- `metadata.db`: durable deduplication and observation state.

Exports are replaced atomically. An agent can therefore read them while the
collector is running. Script contents are deduplicated by SHA-256 while every
observed page origin is retained.

## Pamphagos integration contract

Pamphagos only needs to start this binary next to the browser, point it at the
browser profile's `DevToolsActivePort`, and expose the output directory in the
agent workspace. SinkSight does not own Chromium and does not add an HTTP
service or an operator UI.

## License

This project is licensed under the GNU General Public License v3.0 or later.
See [LICENSE](LICENSE) for the full terms.
