/* tslint:disable */
/* eslint-disable */
export interface AnalyzeResult {
    findings: Finding[];
    structuralHash: string;
    library?: LibraryCheck;
    analysisError?: string;
}

export interface Finding {
    detectorName: string;
    category: FindingCategory;
    startOffset: number;
    endOffset: number;
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
    snippet: string;
}

export interface FunctionMatch {
    libs: LibraryMatch[];
    functionName: string | null;
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
}

export interface LibraryCheck {
    wholeFile: LibraryMatch[];
    functions: FunctionMatch[];
}

export interface LibraryMatch {
    lib: string;
    version: string;
}

export type FindingCategory = "sink" | "input";


export class Engine {
    free(): void;
    [Symbol.dispose](): void;
    analyze(source: string): AnalyzeResult;
    /**
     * `libraryDb` is the raw `.slhdb` bytes. Pass `undefined` to analyze without a library database.
     */
    constructor(library_db?: Uint8Array | null);
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_engine_free: (a: number, b: number) => void;
    readonly engine_analyze: (a: number, b: number, c: number) => any;
    readonly engine_new: (a: number, b: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
