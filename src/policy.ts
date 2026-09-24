export const signalFields = [
  "geo.country",
  "geo.region",
  "geo.city",
  "network.ip",
  "network.asn",
  "network.organization",
  "client.bot",
  "client.automation",
  "client.headless",
  "client.uaMismatch",
  "device.type",
  "device.os",
  "request.hostname",
  "request.path",
  "request.probe",
  "request.pathEnumeration",
  "request.method",
  "request.referrer",
  "campaign.source",
  "campaign.medium",
  "campaign.name",
] as const;

export type SignalField = (typeof signalFields)[number];
export type Scalar = string | number | boolean;
export type DeviceType = "bot" | "desktop" | "mobile" | "tablet";
export const automationKinds = ["declared", "suspected", "unknown"] as const;
export type AutomationKind = (typeof automationKinds)[number];
export const fingerprintBooleanFields = ["client.headless", "client.uaMismatch", "request.probe", "request.pathEnumeration"] as const;

export type TrafficSignals = {
  [Field in SignalField]?: Scalar | undefined;
} & {
  "device.type"?: DeviceType | undefined;
  "client.automation"?: AutomationKind | undefined;
  "client.headless"?: boolean | undefined;
  "client.uaMismatch"?: boolean | undefined;
  "request.probe"?: boolean | undefined;
  "request.pathEnumeration"?: boolean | undefined;
};

export type Operator = "eq" | "neq" | "in" | "notIn" | "contains" | "startsWith" | "exists";

export interface Condition {
  field: SignalField;
  operator: Operator;
  value?: Scalar | Scalar[];
}

export type Action =
  | { type: "allow" }
  | { type: "block"; status: 403 | 404 | 410; body?: string }
  | { type: "redirect"; status: 301 | 302 | 307 | 308; url: string; preservePath?: boolean }
  | { type: "route"; origin: string };

export interface Rule {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  match: "all" | "any";
  conditions: Condition[];
  action: Action;
}

export interface AttributionConfig {
  enabled: true;
  partnerQueryParameter?: string;
  entryQueryPrefixes?: string[];
}

export interface PublishedConfig {
  schemaVersion: 1 | 2;
  propertyId: string;
  version: number;
  domains: string[];
  defaultOrigin?: string;
  defaultAction?: Extract<Action, { type: "redirect" }>;
  rules: Rule[];
  attribution?: AttributionConfig;
}

const operators = new Set<Operator>(["eq", "neq", "in", "notIn", "contains", "startsWith", "exists"]);
const fields = new Set<string>(signalFields);
const blockStatuses = new Set([403, 404, 410]);
const redirectStatuses = new Set([301, 302, 307, 308]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isScalar(value: unknown): value is Scalar {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function requireString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${path} must be a non-empty string`);
  return value;
}

function parseHostname(value: unknown, path: string): string {
  const hostname = requireString(value, path).toLowerCase();
  if (hostname === "localhost" || hostname.includes(":")) throw new Error(`${path} must be a DNS hostname`);
  const labels = hostname.split(".");
  const validLabels = labels.every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
  );
  const isIpv4Literal = labels.length === 4 && labels.every((label) => /^\d{1,3}$/.test(label));
  if (hostname.length > 253 || labels.length < 2 || !validLabels || isIpv4Literal) {
    throw new Error(`${path} must be a valid lowercase DNS hostname`);
  }
  return hostname;
}

function parseExternalUrl(value: unknown, path: string, originOnly: boolean): string {
  const raw = requireString(value, path);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${path} must be an absolute URL`);
  }

  if (url.protocol !== "https:" || url.username || url.password) {
    throw new Error(`${path} must be an HTTPS URL without credentials`);
  }
  parseHostname(url.hostname, `${path} hostname`);
  if (originOnly && (url.pathname !== "/" || url.search || url.hash)) {
    throw new Error(`${path} must contain only an HTTPS origin`);
  }
  return url.toString();
}

function parseCondition(value: unknown, path: string): Condition {
  if (!isRecord(value)) throw new Error(`${path} must be an object`);
  const field = requireString(value.field, `${path}.field`);
  const operator = requireString(value.operator, `${path}.operator`);
  if (!fields.has(field)) throw new Error(`${path}.field is unsupported`);
  if (!operators.has(operator as Operator)) throw new Error(`${path}.operator is unsupported`);

  const typedOperator = operator as Operator;
  if (typedOperator === "exists") {
    return { field: field as SignalField, operator: typedOperator };
  }

  if (field === "client.automation" || fingerprintBooleanFields.some((item) => item === field)) {
    if (!["eq", "neq", "in", "notIn"].includes(typedOperator)) {
      throw new Error(`${path}.operator is unsupported for this signal`);
    }
    const values = Array.isArray(value.value) ? value.value : [value.value];
    const valid = values.every((item) => field === "client.automation"
      ? automationKinds.some((kind) => kind === item)
      : typeof item === "boolean");
    if (!valid) throw new Error(`${path}.value has an invalid signal value`);
  }

  if (typedOperator === "in" || typedOperator === "notIn") {
    if (!Array.isArray(value.value) || value.value.length === 0 || !value.value.every(isScalar)) {
      throw new Error(`${path}.value must be a non-empty scalar array`);
    }
    return { field: field as SignalField, operator: typedOperator, value: value.value };
  }

  if (!isScalar(value.value)) throw new Error(`${path}.value must be a scalar`);
  return { field: field as SignalField, operator: typedOperator, value: value.value };
}

function parseAction(value: unknown, path: string): Action {
  if (!isRecord(value)) throw new Error(`${path} must be an object`);
  const type = requireString(value.type, `${path}.type`);

  if (type === "allow") return { type };
  if (type === "block") {
    if (typeof value.status !== "number" || !blockStatuses.has(value.status)) {
      throw new Error(`${path}.status must be 403, 404, or 410`);
    }
    if (value.body !== undefined && typeof value.body !== "string") {
      throw new Error(`${path}.body must be a string`);
    }
    if (typeof value.body === "string" && value.body.length > 500) {
      throw new Error(`${path}.body must not exceed 500 characters`);
    }
    return {
      type,
      status: value.status as 403 | 404 | 410,
      ...(typeof value.body === "string" ? { body: value.body } : {}),
    };
  }
  if (type === "redirect") {
    if (typeof value.status !== "number" || !redirectStatuses.has(value.status)) {
      throw new Error(`${path}.status must be 301, 302, 307, or 308`);
    }
    if (value.preservePath !== undefined && typeof value.preservePath !== "boolean") {
      throw new Error(`${path}.preservePath must be a boolean`);
    }
    return {
      type,
      status: value.status as 301 | 302 | 307 | 308,
      url: parseExternalUrl(value.url, `${path}.url`, false),
      ...(typeof value.preservePath === "boolean" ? { preservePath: value.preservePath } : {}),
    };
  }
  if (type === "route") {
    return { type, origin: parseExternalUrl(value.origin, `${path}.origin`, true) };
  }
  throw new Error(`${path}.type is unsupported`);
}

function parseRule(value: unknown, index: number): Rule {
  const path = `rules[${index}]`;
  if (!isRecord(value)) throw new Error(`${path} must be an object`);
  if (typeof value.enabled !== "boolean") throw new Error(`${path}.enabled must be a boolean`);
  if (!Number.isSafeInteger(value.priority)) throw new Error(`${path}.priority must be an integer`);
  if (value.match !== "all" && value.match !== "any") throw new Error(`${path}.match must be all or any`);
  if (!Array.isArray(value.conditions) || value.conditions.length === 0) {
    throw new Error(`${path}.conditions must be a non-empty array`);
  }

  return {
    id: requireString(value.id, `${path}.id`),
    name: requireString(value.name, `${path}.name`),
    enabled: value.enabled,
    priority: value.priority as number,
    match: value.match,
    conditions: value.conditions.map((condition, conditionIndex) =>
      parseCondition(condition, `${path}.conditions[${conditionIndex}]`),
    ),
    action: parseAction(value.action, `${path}.action`),
  };
}

function parseQueryParameterName(value: unknown, path: string): string {
  const name = requireString(value, path);
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name)) {
    throw new Error(`${path} must be a valid query parameter name`);
  }
  return name;
}

function parseAttribution(value: unknown): AttributionConfig | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new Error("attribution must be an object");
  if (value.enabled !== true) throw new Error("attribution.enabled must be true");

  let entryQueryPrefixes: string[] | undefined;
  if (value.entryQueryPrefixes !== undefined) {
    if (!Array.isArray(value.entryQueryPrefixes) || value.entryQueryPrefixes.length > 8) {
      throw new Error("attribution.entryQueryPrefixes must be an array with at most 8 values");
    }
    entryQueryPrefixes = value.entryQueryPrefixes.map((prefix, index) =>
      parseQueryParameterName(prefix, `attribution.entryQueryPrefixes[${index}]`)
    );
    if (new Set(entryQueryPrefixes).size !== entryQueryPrefixes.length) {
      throw new Error("attribution.entryQueryPrefixes must be unique");
    }
  }

  return {
    enabled: true,
    ...(value.partnerQueryParameter === undefined
      ? {}
      : {
          partnerQueryParameter: parseQueryParameterName(
            value.partnerQueryParameter,
            "attribution.partnerQueryParameter",
          ),
        }),
    ...(entryQueryPrefixes ? { entryQueryPrefixes } : {}),
  };
}

export function parsePublishedConfig(value: unknown): PublishedConfig {
  if (!isRecord(value)) throw new Error("config must be an object");
  if (value.schemaVersion !== 1 && value.schemaVersion !== 2) throw new Error("schemaVersion must be 1 or 2");
  if (!Number.isSafeInteger(value.version) || (value.version as number) < 1) {
    throw new Error("version must be a positive integer");
  }
  if (!Array.isArray(value.domains) || value.domains.length === 0) {
    throw new Error("domains must be a non-empty array");
  }
  if (!Array.isArray(value.rules)) throw new Error("rules must be an array");

  const domains = value.domains.map((domain, index) => parseHostname(domain, `domains[${index}]`));
  if (new Set(domains).size !== domains.length) throw new Error("domains must be unique");
  if (value.schemaVersion === 2 && domains.length !== 1) throw new Error("schemaVersion 2 requires one ingress domain");

  const rules = value.rules.map(parseRule);
  const ruleIds = rules.map((rule) => rule.id);
  if (new Set(ruleIds).size !== ruleIds.length) throw new Error("rule ids must be unique");

  let defaultOrigin: string | undefined;
  let defaultAction: Extract<Action, { type: "redirect" }> | undefined;
  if (value.schemaVersion === 1) {
    if (value.defaultAction !== undefined) throw new Error("schemaVersion 1 cannot use defaultAction");
    defaultOrigin = parseExternalUrl(value.defaultOrigin, "defaultOrigin", true);
  } else {
    if (value.defaultOrigin !== undefined) throw new Error("schemaVersion 2 cannot use defaultOrigin");
    const action = parseAction(value.defaultAction, "defaultAction");
    if (action.type !== "redirect") throw new Error("defaultAction must be a redirect");
    if (rules.some((rule) => rule.action.type === "allow" || rule.action.type === "route")) {
      throw new Error("schemaVersion 2 rules must redirect or block");
    }
    defaultAction = action;
  }
  const destinationHosts = [
    ...(defaultOrigin ? [new URL(defaultOrigin).hostname] : []),
    ...(defaultAction ? [new URL(defaultAction.url).hostname] : []),
    ...rules.flatMap((rule) => {
      if (rule.action.type === "route") return [new URL(rule.action.origin).hostname];
      if (rule.action.type === "redirect") return [new URL(rule.action.url).hostname];
      return [];
    }),
  ];
  if (destinationHosts.some((hostname) => domains.includes(hostname))) {
    throw new Error("an origin or redirect target cannot be a managed domain");
  }

  const propertyId = requireString(value.propertyId, "propertyId");
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(propertyId)) {
    throw new Error("propertyId must be 1-64 lowercase letters, numbers, underscores, or dashes");
  }

  const attribution = parseAttribution(value.attribution);

  return {
    schemaVersion: value.schemaVersion,
    propertyId,
    version: value.version as number,
    domains,
    ...(defaultOrigin ? { defaultOrigin } : {}),
    ...(defaultAction ? { defaultAction } : {}),
    rules,
    ...(attribution ? { attribution } : {}),
  };
}

export function defaultTarget(config: PublishedConfig): string {
  return config.schemaVersion === 2 ? config.defaultAction!.url : config.defaultOrigin!;
}
