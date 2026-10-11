import { buildFeatureSnapshot, computeFeatureSnapshotId, type SourceDefinition } from "../../src/web.js";

export default {
  async fetch(request: Request): Promise<Response> {
    const input = await request.json() as { gzip: string; failValidation?: boolean; nativeFetch?: boolean };
    const sources: SourceDefinition[] = [
      { id: "iptoasn-v4", url: "https://example.com/asn", license: "PDDL-1.0", format: "asn-tsv-gzip", minRecords: 1 },
      { id: "vpn", url: "https://example.com/vpn", license: "MIT", format: "cidr", minRecords: 1 },
      { id: "datacenter", url: "https://example.com/datacenter", license: "MIT", format: "cidr", minRecords: 1 },
      { id: "crawlers", url: "https://example.com/crawlers", license: "MIT", format: "crawler-json", minRecords: 1 },
    ];
    const payloads: Record<string, string | Uint8Array<ArrayBuffer>> = {
      asn: Uint8Array.from(atob(input.gzip), (character) => character.charCodeAt(0)),
      vpn: "192.0.2.128/25\n", datacenter: "192.0.2.0/24\n",
      crawlers: JSON.stringify([{ pattern: "ExampleBot\\/", url: "https://example.com/bot" }]),
    };
    let validated = false;
    try {
      const snapshot = await buildFeatureSnapshot({
        sources, now: new Date("2026-10-11T00:00:00.000Z"),
        ...(input.nativeFetch ? {} : { fetcher: async (url: string | URL | Request, init?: RequestInit) => {
          if (init?.redirect !== "manual") throw new Error("Redirects must not be followed");
          return new Response(payloads[new URL(String(url)).pathname.slice(1)]!);
        } }),
        async validateSnapshot(candidate) {
          if (input.failValidation) throw new Error("Host shard validation failed");
          validated = candidate.sources.length === 4;
        },
      });
      return Response.json({ snapshot, validated, checksum: await computeFeatureSnapshotId(snapshot),
        nodeGlobals: { process: typeof globalThis.process, buffer: typeof globalThis.Buffer } });
    } catch (error) { return Response.json({ error: (error as Error).message }, { status: 422 }); }
  },
};
