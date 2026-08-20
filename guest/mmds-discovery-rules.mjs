export const DIRECT_SECRET_LEAVES = Object.freeze([
  "DD_API_KEY", "DATADOG_API_KEY", "datadog_api_key", "datadog-api-key",
  "api_key", "apiKey", "api-key", "api_token", "apiToken", "api-token",
  "token", "credential", "credentials",
]);

export const DISCOVERY_NAMESPACE_RULES = Object.freeze({
  datadog: Object.freeze([
    "api_key", "apiKey", "api-key", "app_key", "appKey", "app-key",
    "token", "credential", "credentials",
  ]),
  secrets: Object.freeze([
    "DD_API_KEY", "DATADOG_API_KEY", "datadog_api_key", "datadog-api-key",
    "api_key", "apiKey", "api-key", "token", "credential", "credentials",
  ]),
  credentials: Object.freeze(["datadog", "api_key", "apiKey", "api-key", "token", "credential"]),
  tokens: Object.freeze(["datadog", "api", "api_token", "apiToken", "api-token", "token"]),
  latest: DIRECT_SECRET_LEAVES,
});

export const SECRET_OBJECT_KEYS = Object.freeze([
  "api_key", "apikey", "apiKey", "api-key", "app_key", "appKey", "app-key",
  "token", "api_token", "apiToken", "api-token", "credential", "credentials",
  "secret", "secret_key", "secretKey", "secret-key", "access_key", "accessKey", "access-key",
]);
