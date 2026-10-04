# SinkSight Engine

SinkSight Engine is a Rust library that analyzes JavaScript for DOM XSS inputs
and sinks. It can optionally identify known library code with a SinkSight
library hash database.

## Rust

The main crate exposes `Analyzer` for repeated analysis with an optional
library database:

```rust
use sinksight_engine::Analyzer;

let analyzer = Analyzer::new(None)?;
let result = analyzer.analyze("document.write(location.hash)");
```

Pamphagos Browser consumes this crate directly. Browser collection,
persistence and user-facing commands belong to Pamphagos Browser rather than
this repository.

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

Build it locally with Rust and
[wasm-pack](https://rustwasm.github.io/wasm-pack/installer/):

```bash
npm run build
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
