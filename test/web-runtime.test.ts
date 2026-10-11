import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { gzipSync } from "node:zlib";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions, Response as MiniflareResponse } from "miniflare";
import type { FeatureSnapshot } from "../src/features.js";
import { createHash } from "node:crypto";

describe("Web entry in Workers without nodejs_compat", () => {
  let runtime: Miniflare;
  beforeAll(async () => {
    const bundle = await build({ entryPoints: [new URL("./fixtures/web-worker.ts", import.meta.url).pathname], bundle: true, platform: "browser", format: "esm", write: false, metafile: true });
    expect(Object.keys(bundle.metafile!.inputs).some((path) => /(?:^|\/)node\.ts$/.test(path) || path.startsWith("node:"))).toBe(false);
    runtime = new Miniflare(convertV4MiniflareOptions({
      modules: true, script: bundle.outputFiles[0]!.text, compatibilityDate: "2026-10-06",
      compatibilityFlags: ["no_nodejs_compat", "no_nodejs_compat_v2"], telemetry: { enabled: false },
      outboundService: async (request) => {
        const name = new URL(request.url).pathname.slice(1);
        const payload: Record<string, string | Uint8Array<ArrayBuffer>> = {
          asn: new Uint8Array(gzipSync("192.0.2.0\t192.0.2.255\t64500\tUnknown\tExample Network\n")),
          vpn: "192.0.2.128/25\n", datacenter: "192.0.2.0/24\n",
          crawlers: JSON.stringify([{ pattern: "ExampleBot\\/", url: "https://example.com/bot" }]),
        };
        return new MiniflareResponse(payload[name]!);
      },
    }));
    await runtime.ready;
  }, 30_000);
  afterAll(async () => { await runtime?.dispose(); });
  const gzip = gzipSync("192.0.2.0\t192.0.2.255\t64500\tUnknown\tExample Network\n").toString("base64");
  it("bundles for browsers and runs download/decompression/hash/host validation using Web APIs only", async () => {
    const response = await runtime.dispatchFetch("https://example.com/build", { method: "POST", body: JSON.stringify({ gzip }) });
    expect(response.status).toBe(200);
    const result = await response.json() as { snapshot: FeatureSnapshot; checksum: string; validated: boolean; nodeGlobals: { process: string; buffer: string } };
    expect(result.nodeGlobals).toEqual({ process: "undefined", buffer: "undefined" });
    expect(result.validated).toBe(true);
    expect(result.snapshot.sources).toHaveLength(4);
    expect(result.snapshot.data.asn[0]!.country).toBe("ZZ");
    const expected = createHash("sha256").update(JSON.stringify({ sources: result.snapshot.sources, data: result.snapshot.data })).digest("hex");
    expect(result.snapshot.id).toBe(expected); expect(result.checksum).toBe(expected);
  });
  it("rejects a candidate when host-specific shard validation fails", async () => {
    const response = await runtime.dispatchFetch("https://example.com/build", { method: "POST", body: JSON.stringify({ gzip, failValidation: true }) });
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "Host shard validation failed" });
  });
  it("uses native Worker Fetch with synthetic outbound feeds and no live provider calls", async () => {
    const response = await runtime.dispatchFetch("https://example.com/build", { method: "POST", body: JSON.stringify({ gzip, nativeFetch: true }) });
    expect(response.status).toBe(200);
    const result = await response.json() as { snapshot: FeatureSnapshot; validated: boolean };
    expect(result.validated).toBe(true);
    expect(result.snapshot.sources.map((source) => source.records)).toEqual([1, 1, 1, 1]);
  });
});
