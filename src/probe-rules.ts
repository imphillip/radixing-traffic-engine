export const PROBE_RULESET_VERSION = 1;

export const probeRuleIds = [
  "env-file",
  "vcs-metadata",
  "cloud-credentials",
  "phpinfo",
  "service-account-key",
] as const;

export type ProbeRuleId = (typeof probeRuleIds)[number];

export interface ProbePathAssessment {
  version: typeof PROBE_RULESET_VERSION;
  probe: boolean;
  rule?: ProbeRuleId;
}

interface ProbeRule {
  id: ProbeRuleId;
  matches: (segment: string) => boolean;
}

const ENV_FILE = /^\.env(?:$|[._~-].*|\d+)$/i;
const PHPINFO_FILE = /^phpinfo(?:\.php)?(?:\.(?:bak|old|save|backup|txt)|~)?$/i;
const SERVICE_ACCOUNT_FILE = /^(?:firebase-adminsdk|firebase-key|application_default_credentials|service-account|gcp-key)\.json$/i;

// The catalog stays intentionally small. Each rule needs a concrete exposure target and replay
// coverage before it becomes a request.probe signal.
const probeRules: readonly ProbeRule[] = [
  { id: "env-file", matches: (segment) => ENV_FILE.test(segment) },
  { id: "vcs-metadata", matches: (segment) => [".git", ".svn"].includes(segment.toLowerCase()) },
  { id: "cloud-credentials", matches: (segment) => segment.toLowerCase() === ".aws" },
  { id: "phpinfo", matches: (segment) => PHPINFO_FILE.test(segment) },
  { id: "service-account-key", matches: (segment) => SERVICE_ACCOUNT_FILE.test(segment) },
];

export function analyzeProbePath(path: string | undefined): ProbePathAssessment | undefined {
  if (!path || !path.startsWith("/")) return undefined;

  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    return undefined;
  }

  const segments = decoded.split("/").filter(Boolean);
  for (const rule of probeRules) {
    if (segments.some(rule.matches)) {
      return { version: PROBE_RULESET_VERSION, probe: true, rule: rule.id };
    }
  }
  return { version: PROBE_RULESET_VERSION, probe: false };
}
