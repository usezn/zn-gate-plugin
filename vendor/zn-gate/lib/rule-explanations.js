'use strict';
/**
 * One table that says, in plain words, what each rule id in the evidence log means, why it
 * matters and whether a person has a command to go on. `zn why` reads it; the block messages
 * can reuse it, so a rule is explained in one place only.
 *
 * Rule ids come from the evidence log (lib/evidence.js): the rules engine (`pi:...`, `secret:...`),
 * the shield (`mcp_tool_changed`, ...) and the hooks (`hook-<event>-secret`, `hook-<event>-policy`).
 * An entry is { name, matters, allow }, where allow is one of:
 *   { command: 'secret set NAME', note }  a command the person can run in their own terminal
 *   { command: null, note, who }          no command exists; `who` says who decides
 * `allow` can be a function of the record, for a command that names something from it.
 * Only put a command here that exists in the CLI: test/why.test.js checks the verbs.
 */

const NO_BYPASS = 'No command lets this through.';

const INJECTION_MATTERS = 'Text like this is how a web page, a file or a tool can give orders to your agent behind your back. ' +
  'If the agent obeyed it, it could act for whoever wrote the text instead of for you.';

const GROUPS = [
  { ids: ['pi:ignore_previous', 'pi:disregard', 'pi:forget', 'pi:new_instructions'], name: 'Text that tells the agent to ignore or replace its earlier instructions' },
  { ids: ['pi:identity_override', 'pi:act_as', 'pi:pretend', 'pi:roleplay'], name: 'Text that tells the agent it is now someone else or should play a different role' },
  { ids: ['pi:system_tag', 'pi:system_bracket', 'pi:template_boundary'], name: 'Text that pretends to be a system message or copies the hidden markers of a chat model' },
  { ids: ['pi:jailbreak', 'pi:bypass', 'pi:override'], name: 'Text that tries to switch off the agent\'s safety rules' },
  { ids: ['pi:identity_request', 'pi:identity_request_multi'], name: 'Text that tells the agent to look up who you are and put it somewhere' },
  { ids: ['pi:multi_es', 'pi:multi_pt', 'pi:multi_fr', 'pi:multi_de', 'pi:multi_ru', 'pi:multi_zh'], name: 'An "ignore your instructions" order written in another language' },
  { ids: ['indirect:html_comment', 'indirect:hidden_tag'], name: 'Instructions hidden in a web page comment or an invisible element' },
  { ids: ['evasion:bidi_override'], name: 'Invisible text-direction characters that make text look different from what a program reads',
    matters: 'What you see and what a program reads can differ, so a harmless-looking line can hide an order.' },
  { ids: ['evasion:base64_smuggling'], name: 'A command that decodes hidden Base64 text and runs it',
    matters: 'The real command is hidden inside encoded text, so neither you nor zn can read what it would do.' },
  { ids: ['exfil:markdown_image'], name: 'An image link that carries data in its web address',
    matters: 'When the image loads, the data in the address is sent to another server, which can leak information without a visible sign.' },
  { ids: ['exfil:credentials'], name: 'Text that asks to read or send passwords or keys',
    matters: 'Passwords and keys that reach a model, or a server it talks to, can be copied and used by someone else.' },
  { ids: ['path:sensitive_file'], name: 'Text that points at a file that usually holds passwords or keys',
    matters: 'Files such as .env or ~/.ssh hold secrets. Secret values never go to the model.' },
];

const SECRET_ALLOW = {
  command: 'secret set NAME',
  note: 'Save the value there (NAME is a name you choose), then have the agent write __ZN_NAME__ where the value goes. The real value stays on your computer.',
};

const TABLE = Object.create(null);
for (const g of GROUPS) {
  for (const id of g.ids) {
    TABLE[id] = { name: g.name, matters: g.matters || INJECTION_MATTERS,
      allow: { command: null, note: NO_BYPASS, who: 'You decide whether to keep using the source of the text.' } };
  }
}

Object.assign(TABLE, {
  'size:truncated': {
    name: 'Text too big to check in full',
    matters: 'Part of it was never scanned, and the part that was not scanned could hold an attack. This record shows it was not passed on unchecked.',
    allow: { command: null, note: 'Ask the tool for a smaller result. This explains the recorded block only; whether an unchecked result is ever passed on depends on how the guard is configured.', who: 'The tool or source has to give less text.' },
  },
  'size:oversize': {
    name: 'Text too big to check in full',
    matters: 'Part of it was never scanned, and the part that was not scanned could hold an attack, so it was held back.',
    allow: { command: null, note: 'Split the input or ask for less.', who: 'The tool or source has to give less text.' },
  },
  'size:nesting': {
    name: 'Data nested too deeply to check',
    matters: 'zn could not walk through all of it, and what it could not read could hold an attack.',
    allow: { command: null, note: 'Ask for a flatter or smaller result.', who: 'The tool or source has to give simpler data.' },
  },
  'size:invisible': {
    name: 'Text that is mostly invisible characters',
    matters: 'Invisible characters can hide text from you while a model still reads it.',
    allow: { command: null, note: NO_BYPASS, who: 'Find where the text came from; you decide whether to trust that source.' },
  },
  'schema_too_large_to_inspect': {
    name: 'A tool description that is too large or too deep to check',
    matters: 'zn could not read all of it, so it did not pass the tool on unchecked.',
    allow: { command: null, note: 'The server has to publish a smaller tool description.', who: 'The author of the MCP server.' },
  },
  'custom:banned_pattern': {
    name: 'A rule of your own project (.znrules or zn.config.json)',
    matters: 'You or your team added this rule on purpose, so zn enforces it as written.',
    allow: { command: null, note: 'Open .znrules or zn.config.json at the root of the project and change or remove the rule.', who: 'You or your team, who own that file.' },
  },
  'custom:forbidden_path': {
    name: 'A path forbidden by a rule of your own project (.znrules or zn.config.json)',
    matters: 'You or your team added this rule on purpose, so zn enforces it as written.',
    allow: { command: null, note: 'Open .znrules or zn.config.json at the root of the project and change or remove the rule.', who: 'You or your team, who own that file.' },
  },
  'custom:invalid_rules': {
    name: 'A rules file of your own project that zn cannot read',
    matters: 'With a rules file zn cannot trust, it stops rather than run without the rules you asked for.',
    allow: { command: null, note: 'Fix the file named in the message, then try again.', who: 'You or your team, who own that file.' },
  },
  'mcp_tool_changed': {
    name: 'An MCP tool is new or different since you approved it',
    matters: 'A server you trusted can change what its tools say, or add tools, after you approved them. That is a way a good server turns bad, so zn asks you first.',
    allow: (rec) => {
      const key = typeof rec.tool_name === 'string' && /^[A-Za-z0-9_.@:-]{1,80}$/.test(rec.tool_name) ? rec.tool_name : '<server>';
      return {
        command: 'pins approve ' + key,
        note: 'Read the changed tools first (`zn pins` lists them). This works only in your own terminal and asks you to type the confirmation. It cannot approve a server that lists the same tool twice or tools without a valid name: the server has to fix that.',
      };
    },
  },
  'mcp_tool_shadowing': {
    name: 'An MCP tool name or text overlaps with a tool of another server',
    matters: 'A tool that copies another tool\'s name or text can trick the agent into calling the wrong one. zn only noted it here; nothing was held back.',
    allow: { command: null, note: 'Nothing to approve: the call was allowed. Check that you trust both servers.', who: 'You decide which servers to keep.' },
  },
  'hook-redacted-output': {
    name: 'Secret values removed from a tool\'s output',
    matters: 'The output held secret values, so zn replaced them with tokens before the model saw them. Nothing was blocked.',
    allow: { command: null, note: 'Nothing to approve. If a value was real and is now in a log or a file you share, rotate it.', who: 'You decide whether to rotate it.' },
  },
  'hook-package-check-not-found': {
    name: 'A package name that does not exist in the public registry',
    matters: 'An agent can invent a package name, and anyone can then publish a malicious package under it.',
    allow: { command: null, note: 'zn only asked; it did not block. Answer in your agent\'s window.', who: 'You, when your agent asks.' },
  },
  'hook-package-check-new': {
    name: 'A package published very recently',
    matters: 'Brand-new packages have no track record, and attackers rely on that.',
    allow: { command: null, note: 'zn only asked; it did not block. Answer in your agent\'s window.', who: 'You, when your agent asks.' },
  },
  'hook-package-check-look-alike': {
    name: 'A package name that looks like a well-known one',
    matters: 'Look-alike names are a common way to get a malicious package installed by mistake.',
    allow: { command: null, note: 'zn only asked; it did not block. Answer in your agent\'s window.', who: 'You, when your agent asks.' },
  },
  'hook-package-check-unavailable': {
    name: 'The package registry gave no answer',
    matters: 'zn could not check the package, so it asked nothing.',
    allow: { command: null, note: 'Nothing to approve.', who: 'You decide whether to install it.' },
  },
});

const EVENT_WORDS = { pre_tool: 'before the agent ran a tool', post_tool: 'on the output of a tool', user_prompt: 'on a prompt you typed' };

/** The explanation for a hook rule id such as `hook-pre_tool-secret`, or null. */
function hookEntry(id) {
  const m = /^hook-(pre_tool|post_tool|user_prompt)-(secret|policy|notice)$/.exec(id);
  if (!m) return null;
  const when = EVENT_WORDS[m[1]];
  if (m[2] === 'secret') {
    return {
      name: 'A secret value in what zn checked ' + when,
      matters: 'A secret that reaches the model can end up in logs, in files or in someone else\'s hands. Secret values never go to the model.',
      allow: m[1] === 'post_tool'
        ? { command: null, note: 'Nothing to approve. If the value was real, rotate it.', who: 'You decide whether to rotate it.' }
        : SECRET_ALLOW,
    };
  }
  if (m[2] === 'notice') {
    return {
      name: 'An instruction file that tries to instruct the agent',
      matters: 'Text in a file can give orders to the agent. In Claude Code zn cannot hold such a file back, so it only recorded it.',
      allow: { command: null, note: 'Nothing was blocked. Read the file and remove the text if you do not trust it.', who: 'You decide whether to trust the file.' },
    };
  }
  return {
    name: 'One of the checks of the zn hooks (' + when + ')',
    matters: 'zn stops an action that could expose secrets, damage the machine, change how zn runs, or leak data. The log does not keep which of these checks fired.',
    allow: { command: null, note: 'The log does not say which check it was, so no single command can be given. The message your agent received names it; see docs/troubleshooting.md, "Block and warn reasons, by family".', who: 'Depends on the check: some actions only you may run in your own terminal, and some zn never lets an agent do.' },
    incomplete: true,
  };
}

const FAMILIES = [
  ['pi:', { name: 'Text that tries to give the agent new orders', matters: INJECTION_MATTERS }],
  ['indirect:', { name: 'Instructions hidden in content the agent reads', matters: INJECTION_MATTERS }],
  ['evasion:', { name: 'Text built to hide what it does', matters: 'What you see and what a program reads can differ.' }],
  ['exfil:', { name: 'An attempt to send data or secrets away', matters: 'Data that leaves your computer cannot be taken back.' }],
  ['path:', { name: 'A file that usually holds secrets', matters: 'Secret values never go to the model.' }],
  ['secret:', { name: 'A secret value, such as a key, a token or a password', matters: 'A secret that reaches the model can end up in logs, in files or in someone else\'s hands.', allow: SECRET_ALLOW }],
  ['size:', { name: 'Text too big or too complicated to check', matters: 'What zn could not check could hold an attack.' }],
  ['custom:', { name: 'A rule of your own project', matters: 'You or your team added the rule on purpose.' }],
];

/**
 * The explanation for a rule id and the record it came from, or null for an id zn does not know.
 * Returns { name, matters, allow, incomplete? } where allow is { command|null, note, who? }.
 */
function explainRule(id, record = {}) {
  if (typeof id !== 'string' || id === '') return null;
  let entry = TABLE[id] || hookEntry(id);
  if (!entry) {
    const fam = FAMILIES.find(([prefix]) => id.startsWith(prefix));
    if (fam) {
      entry = { ...fam[1], allow: fam[1].allow || { command: null, note: NO_BYPASS, who: 'You decide whether to trust the source.' } };
    }
  }
  if (!entry) return null;
  const allow = typeof entry.allow === 'function' ? entry.allow(record) : entry.allow;
  return { name: entry.name, matters: entry.matters, allow, incomplete: entry.incomplete === true };
}

module.exports = { explainRule, EXPLAINED_IDS: Object.keys(TABLE) };
