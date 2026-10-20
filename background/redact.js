/**
 * MY LAPTOP GUARD - Sensitive Data Redactor
 * Masks tokens, passwords, bearer authorization headers, connection strings,
 * and secret query parameters from stored telemetry and script summaries.
 */

const REDACTION_PATTERNS = [
  // Bearer tokens & Authorization headers
  {
    regex: /(bearer\s+)[a-zA-Z0-9_\-\.]{15,}/gi,
    replace: '$1[REDACTED_BEARER_TOKEN]'
  },
  // API Keys / Secrets in command lines or URLs (e.g. key=..., api_key=..., secret=..., token=...)
  {
    regex: /((?:api[-_]?key|access[-_]?token|auth[-_]?token|client[-_]?secret|private[-_]?key|passwd|password|secret|pwd|token)\s*[=:]\s*["']?)[^\s"'&;,]{4,}(["']?)/gi,
    replace: '$1[REDACTED_SECRET]$2'
  },
  // Basic Auth / Credentials in URIs (e.g. https://user:pass@host)
  {
    regex: /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^:\/\s]+):([^@\/\s]+)@/gi,
    replace: '$1$2:[REDACTED_PASSWORD]@'
  },
  // PowerShell base64 encoded strings (e.g. -enc, -EncodedCommand)
  {
    regex: /(-(?:enc|encodedcommand)\s+)([A-Za-z0-9+/=]{20,})/gi,
    replace: (match, p1, p2) => `${p1}[REDACTED_BASE64_LEN_${p2.length}]`
  },
  // Private Key blocks
  {
    regex: /-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC)?\s*PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA|OPENSSH|DSA|EC)?\s*PRIVATE\s+KEY-----/gi,
    replace: '[REDACTED_PRIVATE_KEY_BLOCK]'
  },
  // Database connection strings containing passwords
  {
    regex: /((?:Server|Data Source|User ID|uid)=[^;]+;.*?(?:Password|pwd)=)[^;]+(;?)/gi,
    replace: '$1[REDACTED_PASSWORD]$2'
  }
];

function redactSensitiveData(input) {
  if (!input || typeof input !== 'string') return input;
  let sanitized = input;

  for (const { regex, replace } of REDACTION_PATTERNS) {
    if (typeof replace === 'function') {
      sanitized = sanitized.replace(regex, replace);
    } else {
      sanitized = sanitized.replace(regex, replace);
    }
  }

  return sanitized;
}

module.exports = {
  redactSensitiveData,
  REDACTION_PATTERNS
};
