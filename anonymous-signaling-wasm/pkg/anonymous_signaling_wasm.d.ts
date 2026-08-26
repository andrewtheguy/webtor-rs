/* tslint:disable */
/* eslint-disable */

export class AnonymousSignalingClient {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  directoryCache(): Promise<any>;
  /**
   * Abort every `connect` still in flight, refuse new ones, and tear the
   * Tor client down.
   */
  close(): Promise<any>;
  /**
   * Bootstrap a Tor client and prove it can reach an onion service.
   *
   * `directory_seed` is the directory data a previous `directoryCache()`
   * returned, or empty. `stun_urls` is used by the WebRTC bridge path;
   * `websocket_bridge` selects the direct Snowflake WebSocket instead.
   */
  static create(directory_seed: string | null | undefined, stun_urls: Array<any>, websocket_bridge: boolean): Promise<any>;
  /**
   * Open a WebSocket to a Nostr relay at `ws://<address>.onion[/path]`.
   *
   * Rejects once `close` has been called, and a call still in flight when
   * `close` happens is aborted rather than left to finish its rendezvous.
   */
  connect(relay_url: string): Promise<any>;
}

export class AnonymousSignalingSocket {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  send(text: string): Promise<any>;
  close(): Promise<any>;
  receive(): Promise<any>;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_anonymoussignalingclient_free: (a: number, b: number) => void;
  readonly __wbg_anonymoussignalingsocket_free: (a: number, b: number) => void;
  readonly anonymoussignalingclient_close: (a: number) => any;
  readonly anonymoussignalingclient_connect: (a: number, b: number, c: number) => any;
  readonly anonymoussignalingclient_create: (a: number, b: number, c: any, d: number) => any;
  readonly anonymoussignalingclient_directoryCache: (a: number) => any;
  readonly anonymoussignalingsocket_close: (a: number) => any;
  readonly anonymoussignalingsocket_receive: (a: number) => any;
  readonly anonymoussignalingsocket_send: (a: number, b: number, c: number) => any;
  readonly wasm_bindgen_80478907236fa2b9___convert__closures_____invoke___web_sys_91ba62fe70348d71___features__gen_CloseEvent__CloseEvent_____: (a: number, b: number, c: any) => void;
  readonly wasm_bindgen_80478907236fa2b9___closure__destroy___dyn_core_e4e32f5ae772ed90___ops__function__FnMut__web_sys_91ba62fe70348d71___features__gen_CloseEvent__CloseEvent____Output_______: (a: number, b: number) => void;
  readonly wasm_bindgen_80478907236fa2b9___convert__closures_____invoke___wasm_bindgen_80478907236fa2b9___JsValue_____: (a: number, b: number, c: any) => void;
  readonly wasm_bindgen_80478907236fa2b9___closure__destroy___dyn_core_e4e32f5ae772ed90___ops__function__FnMut__wasm_bindgen_80478907236fa2b9___JsValue____Output_______: (a: number, b: number) => void;
  readonly wasm_bindgen_80478907236fa2b9___convert__closures_____invoke______: (a: number, b: number) => void;
  readonly wasm_bindgen_80478907236fa2b9___closure__destroy___dyn_core_e4e32f5ae772ed90___ops__function__FnMut_____Output_______: (a: number, b: number) => void;
  readonly wasm_bindgen_80478907236fa2b9___convert__closures_____invoke___wasm_bindgen_80478907236fa2b9___JsValue__wasm_bindgen_80478907236fa2b9___JsValue_____: (a: number, b: number, c: any, d: any) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
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
