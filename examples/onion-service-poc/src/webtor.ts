import webtorWasmUrl from '@andrewtheguy/webtor-wasm/webtor_wasm_bg.wasm?url';

type WebtorModule = typeof import('@andrewtheguy/webtor-wasm');

let modulePromise: Promise<WebtorModule> | undefined;

/** Load the generated JS glue and point it at Vite's emitted WASM asset. */
export function loadWebtor(): Promise<WebtorModule> {
  modulePromise ??= import('@andrewtheguy/webtor-wasm')
    .then(async (module) => {
      await module.default({ module_or_path: webtorWasmUrl });
      return module;
    })
    .catch((error: unknown) => {
      modulePromise = undefined;
      throw error;
    });
  return modulePromise;
}
