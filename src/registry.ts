import type {
  BuildContext,
  BuiltTest,
  ProbeCase,
  TestDefinition,
} from "./contracts.js";

function observerHost(context: BuildContext): string {
  return new URL(context.observerBaseUrl).hostname;
}

function pathWithRun(context: BuildContext, path: string): string {
  return `/v1/probe/${context.runId}${path}`;
}

function canaryPolicy(
  context: BuildContext,
  match: Record<string, unknown>,
): BuiltTest["policy"] {
  return {
    allow: {
      [observerHost(context)]: [
        {
          match,
          transform: [{ headers: { [context.canaryHeader]: context.brokeredCanary } }],
        },
      ],
    },
  };
}

const controlAllow: TestDefinition = {
  id: "CONTROL-ALLOW",
  title: "Observer allow-all positive control",
  priority: "baseline",
  description: "Confirms the guest can reach the observer before interpreting negative network evidence.",
  build(context) {
    return {
      policy: "allow-all",
      cases: [
        {
          id: "allow-all",
          description: "Ordinary HTTPS request under allow-all",
          method: "GET",
          rawPath: pathWithRun(context, "/control/allow-all"),
          expectedNetwork: "hit",
          expectedCanary: "ignore",
        },
      ],
    };
  },
};

const controlDeny: TestDefinition = {
  id: "CONTROL-DENY",
  title: "Deny-all HTTP egress baseline",
  priority: "baseline",
  description: "A one-time observer canary must not leave a deny-all sandbox.",
  build(context) {
    return {
      policy: "deny-all",
      cases: [
        {
          id: "deny-all",
          description: "Ordinary HTTPS request under deny-all",
          method: "GET",
          rawPath: pathWithRun(context, "/control/deny-all"),
          expectedNetwork: "blocked",
          expectedCanary: "ignore",
        },
      ],
    };
  },
};

const headerOverwrite: TestDefinition = {
  id: "SBX-012",
  title: "Brokered credential overwrite semantics",
  priority: "P0",
  description: "Checks whether guest-selected duplicate or differently cased values survive a host-side header transform.",
  build(context) {
    const path = pathWithRun(context, "/headers");
    const cases: ProbeCase[] = [
      {
        id: "broker-control",
        description: "No guest header; the brokered canary must arrive",
        method: "GET",
        rawPath: path,
        expectedNetwork: "hit",
        expectedCanary: "present",
      },
      {
        id: "guest-value",
        description: "Guest supplies the transformed header name",
        method: "GET",
        rawPath: path,
        headers: { [context.canaryHeader]: "guest-controlled-value" },
        expectedNetwork: "hit",
        expectedCanary: "present",
      },
      {
        id: "duplicate-values",
        description: "Guest supplies duplicate values for the transformed header",
        method: "GET",
        rawPath: path,
        headers: { [context.canaryHeader]: ["guest-first", "guest-second"] },
        expectedNetwork: "hit",
        expectedCanary: "present",
      },
    ];
    return {
      policy: canaryPolicy(context, { path: { exact: path } }),
      cases,
      notes: ["Review rawHeaders if any guest-controlled value survives alongside the brokered canary."],
    };
  },
};

const pathNormalization: TestDefinition = {
  id: "SBX-013",
  title: "L7 path normalization",
  priority: "P0",
  description: "Looks for a difference between firewall path matching and the path received by the origin.",
  build(context) {
    const allowedPrefix = pathWithRun(context, "/matched/");
    const outside = pathWithRun(context, "/outside");
    return {
      policy: canaryPolicy(context, { path: { startsWith: allowedPrefix } }),
      cases: [
        {
          id: "matched-control",
          description: "Canonical matching path",
          method: "GET",
          rawPath: `${allowedPrefix}control`,
          expectedNetwork: "hit",
          expectedCanary: "present",
        },
        {
          id: "literal-dotdot",
          description: "Literal dot segment resolves outside the matched prefix",
          method: "GET",
          rawPath: `${allowedPrefix}../outside`,
          expectedNetwork: "hit",
          expectedCanary: "absent",
        },
        {
          id: "encoded-dotdot",
          description: "Percent-encoded dot segment",
          method: "GET",
          rawPath: `${allowedPrefix}%2e%2e/outside`,
          expectedNetwork: "hit",
          expectedCanary: "absent",
        },
        {
          id: "encoded-slash",
          description: "Encoded separator control remains within the backend's canonical path",
          method: "GET",
          rawPath: `${allowedPrefix}..%2foutside`,
          expectedNetwork: "hit",
          expectedCanary: "present",
        },
        {
          id: "outside-control",
          description: "Canonical nonmatching path",
          method: "GET",
          rawPath: outside,
          expectedNetwork: "hit",
          expectedCanary: "absent",
        },
      ],
    };
  },
};

const queryAmbiguity: TestDefinition = {
  id: "SBX-014",
  title: "Query matcher ambiguity",
  priority: "P0",
  description: "Checks exact query matching against suffix, encoding, and duplicate-key cases.",
  build(context) {
    const path = pathWithRun(context, "/query");
    return {
      policy: canaryPolicy(context, {
        path: { exact: path },
        queryString: [{ key: { exact: "tier" }, value: { exact: "privileged" } }],
      }),
      cases: [
        {
          id: "query-control",
          description: "Exact matching key and value",
          method: "GET",
          rawPath: `${path}?tier=privileged`,
          expectedNetwork: "hit",
          expectedCanary: "present",
        },
        {
          id: "value-suffix",
          description: "Nonmatching value suffix",
          method: "GET",
          rawPath: `${path}?tier=privileged-x`,
          expectedNetwork: "hit",
          expectedCanary: "absent",
        },
        {
          id: "encoded-ampersand",
          description: "Encoded separator remains part of the value",
          method: "GET",
          rawPath: `${path}?tier=privileged%26role%3Dadmin`,
          expectedNetwork: "hit",
          expectedCanary: "absent",
        },
        {
          id: "plus-suffix",
          description: "Plus decodes to a trailing space",
          method: "GET",
          rawPath: `${path}?tier=privileged+`,
          expectedNetwork: "hit",
          expectedCanary: "absent",
        },
        {
          id: "duplicate-unprivileged-first",
          description: "Duplicate key uses documented any-matching-value semantics",
          method: "GET",
          rawPath: `${path}?tier=unprivileged&tier=privileged`,
          expectedNetwork: "hit",
          expectedCanary: "present",
        },
      ],
      notes: ["Vercel documents that any matching value satisfies a query matcher when a key has multiple values."],
    };
  },
};

const methodMatching: TestDefinition = {
  id: "SBX-015",
  title: "HTTP method matching",
  priority: "P0",
  description: "Verifies a POST-only broker rule does not transform alternate or override-style methods.",
  build(context) {
    const path = pathWithRun(context, "/method");
    const alternate = (id: string, method: string, headers?: Record<string, string>): ProbeCase => ({
      id,
      description: `${method} must not match a POST-only transform`,
      method,
      rawPath: path,
      ...(headers ? { headers } : {}),
      expectedNetwork: "hit",
      expectedCanary: "absent",
    });
    return {
      policy: canaryPolicy(context, {
        path: { exact: path },
        method: ["POST"],
      }),
      cases: [
        {
          id: "post-control",
          description: "Canonical matching method",
          method: "POST",
          rawPath: path,
          expectedNetwork: "hit",
          expectedCanary: "present",
        },
        alternate("get", "GET"),
        alternate("head", "HEAD"),
        alternate("options", "OPTIONS"),
        alternate("override-header", "GET", { "x-http-method-override": "POST" }),
      ],
    };
  },
};

export const testRegistry: readonly TestDefinition[] = [
  controlAllow,
  controlDeny,
  headerOverwrite,
  pathNormalization,
  queryAmbiguity,
  methodMatching,
];

export function getTest(id: string): TestDefinition | undefined {
  return testRegistry.find((test) => test.id.toLowerCase() === id.toLowerCase());
}
