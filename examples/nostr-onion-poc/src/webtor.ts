import webtorWasmUrl from '@andrewtheguy/webtor-wasm/webtor_wasm_bg.wasm?url';

type WebtorModule = typeof import('@andrewtheguy/webtor-wasm');

let modulePromise: Promise<WebtorModule> | undefined;

/** Load the generated JS glue and point it at Vite's emitted WASM asset. */
async function initWebtor(): Promise<WebtorModule> {
  try {
    const module = await import('@andrewtheguy/webtor-wasm');
    await module.default({ module_or_path: webtorWasmUrl });
    return module;
  } catch (error) {
    modulePromise = undefined;
    throw error;
  }
}

/** Every caller shares one load; a failed one is retried by the next. */
export async function loadWebtor(): Promise<WebtorModule> {
  modulePromise ??= initWebtor();
  return await modulePromise;
}
