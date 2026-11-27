'use strict';

/**
 * The settings of the package install check (lib/package-check.js), read without loading the check itself, so a hook
 * with the check off pays for nothing but this small file.
 *
 * ~/.zn/config.json:
 *   {"hooks": {"packageInstallCheck": "off" | "offline" | "online" | true | false,
 *              "packageInstallAllow": ["name", "@scope/*"],
 *              "packageInstallNewDays": 14,
 *              "packageInstallNotices": true | false | ["fresh_version", "no_lockfile"]}}
 * ZN_PACKAGE_CHECK=offline (or 1) turns on the offline mode from the environment. The environment can only add the
 * offline mode: ZN_PACKAGE_CHECK=online is read as offline, because the project an agent works in can set environment
 * variables and must not be able to make zn contact a registry. Only the config file turns the online mode on.
 *
 * Notices are a second, opt-in layer on the same check. They are only notes: they never ask and never block.
 * "fresh_version" (online mode only) notes a version published less than 72 hours ago; "no_lockfile" notes an
 * `npm install` (not `npm ci`). Off unless the config file lists them (or sets true for both).
 */

const MODES = new Set(['off', 'offline', 'online']);
const DEFAULT_NEW_DAYS = 14;
const NOTICE_KINDS = new Set(['fresh_version', 'no_lockfile']);
const FRESH_HOURS = 72;

function modeOf(setting, envValue) {
  let mode = 'off';
  const v = typeof setting === 'string' ? setting.toLowerCase() : setting;
  if (v === true) mode = 'offline';
  else if (typeof v === 'string' && MODES.has(v)) mode = v;
  const env = String(envValue || '').toLowerCase();
  if (mode === 'off' && (env === 'offline' || env === 'online' || env === '1')) mode = 'offline';
  return mode;
}

/* Allow-list entries: names (PyPI names are normalised when compared) and `@scope/*` for a whole npm scope. */
function allowOf(value) {
  return Array.isArray(value)
    ? value.filter((x) => typeof x === 'string' && x.length <= 214 && /^[A-Za-z0-9@][A-Za-z0-9@._~/*-]*$/.test(x)).map((x) => x.toLowerCase()).slice(0, 256)
    : [];
}

function newDaysOf(value) {
  return Number.isInteger(value) && value >= 1 && value <= 365 ? value : DEFAULT_NEW_DAYS;
}

/* The notices switched on: a Set of NOTICE_KINDS. Nothing unless the config file asks for it. */
function noticesOf(value) {
  if (value === true) return new Set(NOTICE_KINDS);
  if (Array.isArray(value)) return new Set(value.filter((x) => NOTICE_KINDS.has(x)));
  return new Set();
}

/** { mode, allow, newDays, notices } from the "hooks" object of the config file, an explicit override (tests) and the environment. */
function settingsOf(hooks, override, env) {
  const h = hooks && typeof hooks === 'object' ? hooks : {};
  const setting = override !== undefined ? override : h.packageInstallCheck;
  return {
    mode: modeOf(setting, env),
    allow: allowOf(h.packageInstallAllow),
    newDays: newDaysOf(h.packageInstallNewDays),
    notices: noticesOf(h.packageInstallNotices),
  };
}

module.exports = { settingsOf, modeOf, allowOf, newDaysOf, noticesOf, DEFAULT_NEW_DAYS, NOTICE_KINDS, FRESH_HOURS };
