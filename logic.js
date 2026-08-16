'use strict';

const TENANT = 'tenant-9hn3crk';
const EMAIL_DOMAIN = 'notify-k72j2xe.example';

const ALLOWED_TOOLS = ['search', 'lookup_record', 'send_email', 'render_html'];

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

function keysExactly(obj, keys) {
  const objKeys = Object.keys(obj);
  if (objKeys.length !== keys.length) return false;
  return keys.every((k) => objKeys.includes(k));
}

// --- Step 1: top-level schema ---
function checkTopLevelSchema(payload) {
  if (!isPlainObject(payload)) return false;

  if (payload.provenance !== 'trusted' && payload.provenance !== 'untrusted') {
    return false;
  }
  if (typeof payload.humanApproved !== 'boolean') {
    return false;
  }
  if (
    payload.untrustedContent !== undefined &&
    typeof payload.untrustedContent !== 'string'
  ) {
    return false;
  }
  if (!isPlainObject(payload.action)) return false;
  if (typeof payload.action.tool !== 'string') return false;
  if (!isPlainObject(payload.action.args)) return false;

  return true;
}

// --- Step 3: per-tool argument schema ---
function checkArgsSchema(tool, args) {
  switch (tool) {
    case 'search': {
      if (!keysExactly(args, ['query'])) return false;
      const { query } = args;
      return (
        typeof query === 'string' && query.length >= 1 && query.length <= 200
      );
    }
    case 'lookup_record': {
      if (!keysExactly(args, ['tenantId', 'recordId'])) return false;
      return (
        typeof args.tenantId === 'string' &&
        isNonEmptyString(args.recordId)
      );
    }
    case 'send_email': {
      if (!keysExactly(args, ['to', 'subject', 'body'])) return false;
      return (
        typeof args.to === 'string' &&
        typeof args.subject === 'string' &&
        typeof args.body === 'string'
      );
    }
    case 'render_html': {
      if (!keysExactly(args, ['html'])) return false;
      return typeof args.html === 'string';
    }
    default:
      return false;
  }
}

// --- Step 6: HTML safety (structural, not phrase-based) ---
const SCRIPT_TAG_RE = /<\s*script\b/i;
const IFRAME_TAG_RE = /<\s*iframe\b/i;
const EVENT_HANDLER_ATTR_RE = /\bon[a-z][a-z0-9-]*\s*=/i;
const JAVASCRIPT_URL_RE = /javascript\s*:/i;

function isUnsafeHtml(html) {
  return (
    SCRIPT_TAG_RE.test(html) ||
    IFRAME_TAG_RE.test(html) ||
    EVENT_HANDLER_ATTR_RE.test(html) ||
    JAVASCRIPT_URL_RE.test(html)
  );
}

function getEmailDomain(address) {
  const at = address.lastIndexOf('@');
  if (at === -1 || at === address.length - 1) return null;
  return address.slice(at + 1);
}

function evaluateActionFirewall(payload) {
  // 1. Top-level schema
  if (!checkTopLevelSchema(payload)) {
    return { decision: 'block', reason: 'INVALID_SCHEMA' };
  }

  const { action, humanApproved } = payload;
  const tool = action.tool;
  const args = action.args;

  // 2. Tool allowlist
  if (!ALLOWED_TOOLS.includes(tool)) {
    return { decision: 'block', reason: 'TOOL_NOT_ALLOWED' };
  }

  // 3. Per-tool argument schema
  if (!checkArgsSchema(tool, args)) {
    return { decision: 'block', reason: 'INVALID_SCHEMA' };
  }

  // 4. Tenant scope
  if (tool === 'lookup_record' && args.tenantId !== TENANT) {
    return { decision: 'block', reason: 'TENANT_SCOPE' };
  }

  // 5. Exact email domain
  if (tool === 'send_email') {
    const domain = getEmailDomain(args.to);
    if (domain !== EMAIL_DOMAIN) {
      return { decision: 'block', reason: 'EGRESS_DENIED' };
    }
  }

  // 6. Human approval
  if (tool === 'send_email' && humanApproved !== true) {
    return { decision: 'block', reason: 'APPROVAL_REQUIRED' };
  }

  // 7. HTML safety
  if (tool === 'render_html' && isUnsafeHtml(args.html)) {
    return { decision: 'block', reason: 'UNSAFE_OUTPUT' };
  }

  return { decision: 'allow', reason: 'ALLOW' };
}

module.exports = { evaluateActionFirewall, TENANT, EMAIL_DOMAIN };
