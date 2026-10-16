'use strict';

const fs = require('fs');
const path = require('path');

/**
 * zn deterministic rules engine - SINGLE SOURCE OF TRUTH.
 * RULES_VERSION: 2026-10-16.6
 */

const RULES_VERSION = '2026-10-16.6';

// Word boundaries are written as explicit ASCII lookarounds, not \b: JavaScript's
// \b is ASCII-only without the u flag, while Python's is Unicode. A letter such
// as "é" next to a trigger word therefore counts as a boundary in both engines,
// so a non-ASCII letter never hides a trigger word.

// "ignore" and "disregard" are ordinary words ("ignore the noise in the
// logs", "ignore whitespace changes"). They only count as an override when
// they name what to ignore: instructions, prompts, rules, guardrails... with a
// qualifier (previous, above, system...) or a quantifier (all, any, your...),
// or point back at earlier text ("ignore the above", "everything before").
// Every group is a fixed list of words and whitespace runs are bounded, so a
// match attempt does bounded work.
const OVERRIDE_NOUN_SOURCE =
  '(?:instructions?|prompts?|rules|guidelines?|directives?|guidance|restrictions?|guardrails?|context|constraints?|commands?|policies|programming|orders|limitations?|directions|requests?|tasks?)(?![A-Za-z0-9_])';
const OVERRIDE_QUANTIFIER_SOURCE = '(?:all|any|every|each|your|my|these|those)(?:\\s{1,32}of)?\\s{1,32}';
const OVERRIDE_DETERMINER_SOURCE = '(?:(?:the|your|my|these|those|our|its|their)\\s{1,32})?';
const OVERRIDE_QUALIFIER_SOURCE =
  '(?:previous|prior|above|earlier|preceding|foregoing|original|initial|existing|system|safety|security|former|developer)\\s{1,32}';
// "ignore the above" / "ignore previous" without a noun counts only at the end
// of a clause, before "and" or before a word for text ("ignore the above
// text"), so "ignore the previous build output" stays allowed.
const OVERRIDE_END_SOURCE =
  '(?=[ \\t]*(?:[.,;:!)\\r\\n]|$)|\\s{1,32}and(?![A-Za-z0-9_])|\\s{1,32}(?:text|content|message|messages|input|lines?|one|ones)(?![A-Za-z0-9_]))';

function overrideRuleSource(verb) {
  return [
    `${verb}\\s{1,32}(?:${OVERRIDE_QUANTIFIER_SOURCE})?${OVERRIDE_DETERMINER_SOURCE}(?:${OVERRIDE_QUALIFIER_SOURCE}){1,2}${OVERRIDE_NOUN_SOURCE}`,
    `${verb}\\s{1,32}${OVERRIDE_QUANTIFIER_SOURCE}${OVERRIDE_DETERMINER_SOURCE}${OVERRIDE_NOUN_SOURCE}`,
    `${verb}\\s{1,32}(?:the\\s{1,32})?(?:instructions|guardrails|directives)(?![A-Za-z0-9_])`,
    `${verb}\\s{1,32}(?:${OVERRIDE_QUANTIFIER_SOURCE})?(?:the\\s{1,32})?(?:previous|prior|above|earlier|preceding|foregoing)${OVERRIDE_END_SOURCE}`,
    `${verb}\\s{1,32}(?:everything|anything|all)\\s{1,32}(?:above|before|previously|prior|earlier|you(?:'ve|\\s{1,32}have|\\s{1,32}were|\\s{1,32}was)?\\s{1,32}(?:been\\s{1,32})?(?:told|said|given|received))(?![A-Za-z0-9_])`,
  ].join('|');
}

// Russian and Chinese rules: a verb followed, within 80 characters on the same
// line, by an object ("забудь ... инструкции", "忽略 ... 指令"). A regex such
// as /忽略[^\n]{0,80}?(指令)/ is linear but reads up to 80 characters from
// every verb, which is slow on a long run of verbs. nearMatch() scans the verbs
// and the objects once each and compares their positions.
const NEAR_MAX_GAP = 80;
const RU_FORGET_RE = /забудь\s+/iu;
const RU_FORGET_OBJECT_RE = /все|инструкции/iu;
const RU_IGNORE_RE = /игнорируй\s+/iu;
const RU_IGNORE_OBJECT_RE = /все|предыдущие/iu;
const RU_PHRASE_RE = /действуй\s+как|ты\s+теперь|найди\s+пароли/iu;
const ZH_IGNORE_RE = /忽略/u;
const ZH_IGNORE_OBJECT_RE = /指示|指令|提示/u;
const ZH_FORGET_RE = /忘记/u;
const ZH_FORGET_OBJECT_RE = /指示|指令|一切/u;
const ZH_PHRASE_RE = /你现在是|初始提示词/u;

// True when an object match starts at most NEAR_MAX_GAP characters after the
// end of a verb match, with no line break in between. Linear: the object
// search only restarts past the last object found.
function nearMatch(text, verbRe, objectRe) {
  const verbs = new RegExp(verbRe.source, verbRe.flags + 'g');
  const objects = new RegExp(objectRe.source, objectRe.flags + 'g');
  let obj = null;
  let v;
  while ((v = verbs.exec(text)) !== null) {
    const end = v.index + v[0].length;
    if (obj === null || obj.index < end) {
      objects.lastIndex = end;
      obj = objects.exec(text);
      if (obj === null) return false;
    }
    if (obj.index - end <= NEAR_MAX_GAP && !text.slice(end, obj.index).includes('\n')) return true;
  }
  return false;
}

function testMultiRu(text) {
  return RU_PHRASE_RE.test(text) || nearMatch(text, RU_FORGET_RE, RU_FORGET_OBJECT_RE) || nearMatch(text, RU_IGNORE_RE, RU_IGNORE_OBJECT_RE);
}

function testMultiZh(text) {
  return ZH_PHRASE_RE.test(text) || nearMatch(text, ZH_IGNORE_RE, ZH_IGNORE_OBJECT_RE) || nearMatch(text, ZH_FORGET_RE, ZH_FORGET_OBJECT_RE);
}

const INJECTION_RULES = [
  { id: 'pi:ignore_previous', pattern: new RegExp(overrideRuleSource('ignore'), 'i'), description: 'Override prior instructions' },
  { id: 'pi:disregard', pattern: new RegExp(overrideRuleSource('disregard'), 'i'), description: 'Disregard instructions' },
  { id: 'pi:forget', pattern: /(?<![A-Za-z0-9_])forget\s+(?:about\s+)?(?:everything|all|your)(?![A-Za-z0-9_])(?!\s+(?:of\s+)?(?:the\s+)?(?:cached?|caches|entries|changes|data|files?|records|sessions?|cookies|state|tabs|devices?|passwords?|history|items|keys|tokens|credentials|settings|preferences|accounts?|connections?|logins?|networks?)(?![A-Za-z0-9_]))/i, description: 'Forget-context attack' },
  { id: 'pi:identity_override', pattern: /you\s+are\s+now/i, description: 'Identity override' },
  { id: 'pi:new_instructions', pattern: /new\s+instructions?:/i, description: 'Instruction replacement' },
  { id: 'pi:system_tag', pattern: /(?:^|[\r\n"'`\[<])[ \t]*system\s*:|<[\s/]*system(?![A-Za-z0-9_])[^<>]*>/i, description: 'Fake system tag' },
  { id: 'pi:system_bracket', pattern: /\[system\]/i, description: 'Bracketed system tag' },
  { id: 'pi:act_as', pattern: /(?:(?<![A-Za-z0-9_])you\s+(?:(?:will|must|should|shall|now)\s+|are\s+to\s+)?|(?:^|[.!?\r\n\u2028\u2029])[ \t]*(?:[\"'`(\[*-][ \t]*)?|(?<![A-Za-z0-9_])please\s+|(?<![A-Za-z0-9_])now\s+|(?<![A-Za-z0-9_])from\s+now\s+on,?\s+(?:you\s+)?)(?=act(?![A-Za-z0-9_]))act\s+as\s+(?:if\s+you(?![A-Za-z0-9_])|an?\s+(?:[a-z-]+\s+){0,3}?(?:ai|assistant|chatbot|bot|model|llm|gpt|persona|character|version|mode|jailbroken|unrestricted|unfiltered|uncensored|evil|malicious|rogue|harmful|unethical|amoral|hacker|dan)(?![A-Za-z0-9_])|my(?![A-Za-z0-9_])|though\s+you(?![A-Za-z0-9_]))/i, description: 'Role hijack (act as)' },
  { id: 'pi:pretend', pattern: /pretend\s+(you|to\s+be)/i, description: 'Role hijack (pretend)' },
  { id: 'pi:roleplay', pattern: /roleplay\s+as/i, description: 'Role hijack (roleplay)' },
  { id: 'pi:jailbreak', pattern: /(?<![A-Za-z0-9_])jailbreak(?![A-Za-z0-9_])/i, description: 'Explicit jailbreak term' },
  { id: 'pi:bypass', pattern: /bypass\s+(your|the|all)/i, description: 'Guardrail bypass attempt' },
  { id: 'pi:override', pattern: /(?<![A-Za-z0-9_])override\s+(?:all\s+|your\s+|the\s+)?(?:system|policy|safety|rules|instructions|guidelines|restrictions)(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])system\s+override\s*:/i, description: 'Policy override attempt' },
  { id: 'pi:template_boundary', pattern: /\[INST\]|\[\/INST\]|<<<SYS>>>|<\/<<SYS>>>|<\|im_start\|>|<\|im_end\|>/i, description: 'Chat template boundary injection' },
  { id: 'pi:multi_es', pattern: /ignora\s+(todas\s+las\s+)?(instrucciones|anteriores|previas)|olvida\s+(todo|las\s+instrucciones)|act[uú]a\s+como|ahora\s+eres/iu, description: 'Multilingual prompt injection (Spanish)' },
  { id: 'pi:multi_pt', pattern: /ignor(?:e|a|em|ar)\s+(?:(?:todas|todos|qualquer|quaisquer|cualquier)\s+)?(?:(?:as|os|las|los|suas|seus|sus|tus|estas|estes|essas|esses)\s+)?(?:instru[cç][oõ]es|instrucciones|regras|reglas|diretrizes|directrices|orienta[cç][oõ]es|ordens|[oó]rdenes|comandos|restri[cç][oõ]es|restricciones|mensagens|anteriores|pr[eé]vias)|ignore\s+(?:tudo|qualquer|quaisquer)(?![A-Za-z0-9_])|ignora\s+(?:todo|tudo|cualquier)(?![A-Za-z0-9_])/i, description: 'Multilingual prompt injection (Portuguese)' },
  { id: 'pi:multi_fr', pattern: /ignore[rz]?\s+(toutes\s+les\s+)?instructions|oublie[rz]?\s+tout|agis\s+comme|tu\s+es\s+maintenant/iu, description: 'Multilingual prompt injection (French)' },
  { id: 'pi:multi_de', pattern: /ignoriere\s+(alle\s+)?(anweisungen|instruktionen)|vergiss\s+(alles|jede)|du\s+bist\s+jetzt|handle\s+als/iu, description: 'Multilingual prompt injection (German)' },
  { id: 'pi:multi_ru', pattern: /забудь\s+[^\n]{0,80}?(все|инструкции)|игнорируй\s+[^\n]{0,80}?(все|предыдущие)|действуй\s+как|ты\s+теперь|найди\s+пароли/iu, test: testMultiRu, description: 'Multilingual prompt injection (Russian)' },
  { id: 'pi:multi_zh', pattern: /忽略[^\n]{0,80}?(指示|指令|提示)|忘记[^\n]{0,80}?(指示|指令|一切)|你现在是|初始提示词/u, test: testMultiZh, description: 'Multilingual prompt injection (Chinese)' },
];

// Hidden-element detection in two linear passes: find the first opening tag
// whose attributes hide it, then search once for a payload keyword after it.
// OPEN_TAG_RE always matches from a "<name" and consumes the attribute run up
// to the next "<" or ">", so every character is read once; the candidate is
// a tag only when that run is closed by ">". (A single regex with a lazy
// `[\s\S]*?` tail, or an attribute run that may cross "<", re-scans the rest
// of the input from every candidate and is super-linear on crafted markup.)
const OPEN_TAG_RE = /<[a-z0-9]+(?![A-Za-z0-9_])([^<>]*)(>?)/gi;
const HIDDEN_ATTR_RE = /(?<![A-Za-z0-9_])(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px)?|color\s*:\s*transparent|text-indent\s*:\s*-[0-9]{3,}px|hidden(?![A-Za-z0-9_]))/i;
const HIDDEN_PAYLOAD_RE = /ignore|system|instruction|prompt|bypass|override|exfil|leak/gi;

// The payload must be in the text of the hidden element itself: its content
// up to the matching close tag (nested tags removed), at most
// HIDDEN_TEXT_CHARS characters after the opening tag. Text after the element
// does not count.
const HIDDEN_TEXT_CHARS = 4096;
const TAG_RE = /<(\/?)([a-z0-9]+)(?![A-Za-z0-9_])[^<>]*>/gi;

// Returns the element's text and the index where reading stopped.
function hiddenElementText(text, start, name) {
  const end = Math.min(text.length, start + HIDDEN_TEXT_CHARS);
  const re = new RegExp(TAG_RE.source, TAG_RE.flags);
  re.lastIndex = start;
  let depth = 1;
  let out = '';
  let pos = start;
  let m;
  while ((m = re.exec(text)) !== null && m.index < end) {
    out += text.slice(pos, m.index) + ' ';
    pos = re.lastIndex;
    if (m[2].toLowerCase() === name) {
      depth += m[1] ? -1 : 1;
      if (depth === 0) return { text: out, stop: pos };
    }
  }
  return { text: out + text.slice(pos, Math.max(pos, end)), stop: Math.max(pos, end) };
}

function testHiddenTag(text) {
  const tagRe = new RegExp(OPEN_TAG_RE.source, OPEN_TAG_RE.flags);
  let m;
  while ((m = tagRe.exec(text)) !== null) {
    if (m[2] === '>' && HIDDEN_ATTR_RE.test(m[1])) {
      const name = m[0].slice(1).match(/^[a-z0-9]+/i)[0].toLowerCase();
      const el = hiddenElementText(text, tagRe.lastIndex, name);
      if (new RegExp(HIDDEN_PAYLOAD_RE.source, 'i').test(el.text)) return true;
      // Hidden elements nested in this one were part of its text: each
      // character is read once.
      tagRe.lastIndex = Math.max(tagRe.lastIndex, el.stop);
    }
  }
  return false;
}

// Earlier, broader form: a hidden element followed anywhere later by a
// payload word. Used only for advisories.
function testHiddenTagAnywhere(text) {
  const tagRe = new RegExp(OPEN_TAG_RE.source, OPEN_TAG_RE.flags);
  let m;
  while ((m = tagRe.exec(text)) !== null) {
    if (m[2] === '>' && HIDDEN_ATTR_RE.test(m[1])) {
      const payloadRe = new RegExp(HIDDEN_PAYLOAD_RE.source, HIDDEN_PAYLOAD_RE.flags);
      payloadRe.lastIndex = tagRe.lastIndex;
      return payloadRe.test(text);
    }
  }
  return false;
}

const INDIRECT_INJECTION_RULES = [
  {
    id: 'indirect:html_comment',
    pattern: /<!--\s*(?:system|instruction|prompt|override|command)\s*:/i,
    description: 'Hidden instruction in HTML comment',
  },
  {
    id: 'indirect:hidden_tag',
    // `.pattern` is the linear tag scanner; the rule itself is test().
    pattern: new RegExp(OPEN_TAG_RE.source, 'i'),
    test: testHiddenTag,
    description: 'Hidden DOM element with injection payload',
  },
];

const EVASION_RULES = [
  {
    id: 'evasion:bidi_override',
    pattern: /[\u202A-\u202E\u2066-\u2069]/,
    description: 'Unicode bidirectional override (Trojan Source evasion attempt)',
  },
];

const EXFIL_VERB_SOURCE = '(?<![A-Za-z0-9_])(give|reveal|send|show|print|expose|leak|paste|dump|read|open|cat|fetch|extract|steal)(?![A-Za-z0-9_])';
const CRED_OBJECT_SOURCE =
  '(?<![A-Za-z0-9_])(passwords?|api[_ -]?keys?|secrets?|credentials?|tokens?|ssh[ _-]?keys?|private[ _-]?keys?|aws_secret[a-z0-9_]*|aws_access[a-z0-9_]*)(?![A-Za-z0-9_])|(?:^|\\s|[\'"\`])\\.env(?:\\.[a-z0-9]+)?(?![A-Za-z0-9_])';

// The verb must start a clause (an instruction, not a description such as
// "this library reads tokens from ...") or be followed by "me"/"us", and the
// credential must follow it in the same clause, within EXFIL_CLAUSE_CHARS
// characters. No multiline flag: line starts are matched by the newline
// itself, so a run of blank lines is read once.
const EXFIL_CLAUSE_CHARS = 80;
const EXFIL_CLAUSE_PREFIX = '(?:^|[.!?;:\\r\\n\\u2028\\u2029])[ \\t]*(?:[\\"\'`(\\[*-][ \\t]*)?|(?<![A-Za-z0-9_])(?:please|now|then|and|also|just|first|immediately|go\\s+ahead\\s+and|(?:can|could|would|will)\\s+you|(?:want|need|ask)\\s+you\\s+to|you\\s+(?:must|should|will|need\\s+to|have\\s+to))\\s+';
const EXFIL_CLAUSE_RE = new RegExp(
  '(?:(?:' + EXFIL_CLAUSE_PREFIX + ')' + EXFIL_VERB_SOURCE + '|' + EXFIL_VERB_SOURCE + '(?=\\s+(?:me|us)(?![A-Za-z0-9_])))' +
    '[^.!?;\\r\\n]{0,' + EXFIL_CLAUSE_CHARS + '}?(?:' + CRED_OBJECT_SOURCE + ')',
  'i'
);

const EXFIL_RULES = [
  {
    id: 'exfil:credentials',
    compound: [new RegExp(EXFIL_VERB_SOURCE, 'i'), new RegExp(CRED_OBJECT_SOURCE, 'i'), EXFIL_CLAUSE_RE],
    description: 'Imperative verb requesting credentials/secrets',
  },
];

// Advisory tier: the broader forms of four rules. They match much benign
// text (documentation, code, role-play requests), so a match does not block:
// the verdict stays "allow" and the result carries `advisory` with the rule.
// A blocking rule always wins over an advisory.
const ADVISORY_RULES = [
  { id: 'exfil:credentials', compound: [new RegExp(EXFIL_VERB_SOURCE, 'i'), new RegExp(CRED_OBJECT_SOURCE, 'i')], description: 'Mentions reading or sending credentials' },
  { id: 'pi:act_as', pattern: /act\s+as\s+(?:if|a)/i, description: 'Role-play request (act as)' },
  { id: 'pi:forget', pattern: /forget\s+(?:about\s+)?(?:everything|all|your)/i, description: 'Asks to forget context' },
  { id: 'indirect:hidden_tag', test: testHiddenTagAnywhere, description: 'Hidden element in markup followed by instruction-like words' },
];

function matchesRule(rule, text) {
  if (rule.compound) return rule.compound.every((re) => re.test(text));
  return rule.test ? rule.test(text) : rule.pattern.test(text);
}

const SENSITIVE_PATH_RULES = [
  {
    id: 'path:sensitive_file',
    pattern: /(?:^|[\s"'`(\[])(?:~|\/home\/[^\s/]+|\/root)?\/?\.(?:ssh\/(?:id_rsa|id_ed25519|authorized_keys)|aws\/credentials|env(?:\.[a-z0-9]+)?)(?![A-Za-z0-9_])|\/etc\/(?:shadow|passwd)(?![A-Za-z0-9_])/i,
    description: 'Targeting sensitive system credentials or environment file',
  },
];

// Markdown image exfiltration: ![alt](http(s)://host/...?key=value ...).
// MD_IMAGE_RE always matches from "![" and consumes the alt text and the URL
// once, so the scan is linear; the URL is then checked in code. Patterns that
// chain a lazy URL with a "[^)]*\)" tail re-scan the rest of the input from
// every "![" when no ")" follows.
const MD_IMAGE_RE = /!\[[^\]]*(?:\]\(([^\s)]*))?/gi;
const MD_URL_SCHEME_RE = /^https?:\/\/[^?&]/i;
const MD_URL_SECRET_PARAM_RE = /[?&](?:key|token|pass|secret|cred|data|val|leak|exfil)=/i;

function testMarkdownImage(text) {
  const closing = text.lastIndexOf(')');
  if (closing === -1) return false;
  const imgRe = new RegExp(MD_IMAGE_RE.source, MD_IMAGE_RE.flags);
  let m;
  while ((m = imgRe.exec(text)) !== null) {
    const url = m[1];
    if (url && imgRe.lastIndex <= closing && MD_URL_SCHEME_RE.test(url) && MD_URL_SECRET_PARAM_RE.test(url.slice(url.indexOf('//') + 2))) return true;
  }
  return false;
}

const MARKDOWN_EXFIL_RULES = [
  {
    id: 'exfil:markdown_image',
    // `.pattern` is the linear image scanner; the rule itself is test().
    pattern: new RegExp(MD_IMAGE_RE.source, 'i'),
    test: testMarkdownImage,
    description: 'Covert exfiltration via markdown image URL parameter',
  },
];

// Default policy by tiers. These heuristic injection rules also match a lot of
// ordinary text (YAML `system:` keys, "bypass the cache", "you are now ready",
// security docs), so by default a match is an advisory: the verdict stays
// "allow" and the result carries `advisory`. Strict mode blocks them:
// options.strict, ZN_STRICT=1, or `"strict": true` in zn.config.json (a line
// `strict` in .znrules). Everything else (credential files, secrets, exfiltration,
// evasion, "ignore previous instructions" and the narrow forms) always blocks.
const ADVISORY_BY_DEFAULT = new Set([
  'pi:identity_override',
  'pi:system_tag',
  'pi:system_bracket',
  'pi:new_instructions',
  'pi:pretend',
  'pi:roleplay',
  'pi:jailbreak',
  'pi:bypass',
  'pi:override',
  'pi:template_boundary',
]);

function strictMode(options, cfg) {
  return (options && options.strict === true) || process.env.ZN_STRICT === '1' || (cfg && cfg.strict === true);
}

// Local custom rules cache (.znrules or zn.config.json)
let customConfig = null;
let lastConfigCheck = 0;

function loadCustomConfig(forceReload = false) {
  const now = Date.now();
  if (!forceReload && customConfig !== null && now - lastConfigCheck < 5000) {
    return customConfig;
  }
  lastConfigCheck = now;
  customConfig = { bannedPatterns: [], forbiddenPaths: [], strict: false };

  const candidates = [
    path.join(process.cwd(), '.znrules'),
    path.join(process.cwd(), 'zn.config.json'),
  ];

  for (const file of candidates) {
    if (fs.existsSync(file)) {
      try {
        if (file.endsWith('.json')) {
          const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
          if (Array.isArray(parsed.bannedPatterns)) {
            customConfig.bannedPatterns = parsed.bannedPatterns.map((p) => new RegExp(p, 'i'));
          }
          if (Array.isArray(parsed.forbiddenPaths)) {
            customConfig.forbiddenPaths = parsed.forbiddenPaths;
          }
          if (parsed.strict === true) customConfig.strict = true;
        } else {
          const lines = fs.readFileSync(file, 'utf8').split('\n');
          for (let line of lines) {
            line = line.trim();
            if (!line || line.startsWith('#')) continue;
            // `secret:` lines feed the scrubber's exact-value layer; they are
            // values, not patterns, and must never be compiled as regexes.
            if (line.startsWith('secret:')) continue;
            if (line === 'strict') { customConfig.strict = true; continue; }
            if (line.startsWith('path:')) {
              customConfig.forbiddenPaths.push(line.slice(5).trim());
            } else {
              customConfig.bannedPatterns.push(new RegExp(line, 'i'));
            }
          }
        }
      } catch (err) {
        // Silently ignore malformed custom configs in production
      }
      break;
    }
  }
  return customConfig;
}

const HOMOGLYPH_MAP = {
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0456': 'i', '\u0455': 's', '\u0443': 'y', '\u0445': 'x',
  '\u0410': 'A', '\u0415': 'E', '\u041e': 'O', '\u0420': 'P', '\u0421': 'C',
  // Dotless i and capital dotted I read as i and I.
  '\u0131': 'i', '\u0130': 'I',
};
// Invisible characters removed before matching: zero-width spaces and joiners,
// word joiner, BOM, soft hyphen, and variation selectors. The Unicode tag
// characters (U+E0000-E007F) and the supplementary variation selectors
// (U+E0100-E01EF) are astral and live in INVISIBLE_ASTRAL_RE.
const ZERO_WIDTH_RE = /[\u200B-\u200D\u2060\uFEFF\u00AD\uFE00-\uFE0F]/g;
const INVISIBLE_ASTRAL_RE = /[\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;
// ASCII-only text needs no compatibility folding.
const NON_ASCII_RE = /[^\x00-\x7f]/;
// Compatibility characters folded for matching, one character at a time: fullwidth
// ASCII variants (including fullwidth punctuation), Latin ligatures, super- and
// subscripts, enclosed alphanumerics and mathematical alphanumerics. Full NFKC
// is not used: some characters (such as U+FDFA) expand to 18 characters, which
// makes the cost of a long input grow far beyond its length.
// A run of fullwidth ASCII (U+FF01-FF5E) folds to ASCII by a fixed offset; the
// other characters of the ranges are looked up in a table computed once.
// The long s (U+017F) and the Kelvin sign (U+212A) are included: they fold to
// s and K, which Python's case-insensitive matching would otherwise read as
// letters of the trigger words on the stripped text.
const COMPAT_FOLD_RE = /[！-～]+|[ﬀ-ﬆſK⁰-₟①-⓿]|[\u{1D400}-\u{1D7FF}]/gu;
const COMPAT_FOLD = new Map();
for (const [lo, hi] of [[0xfb00, 0xfb06], [0x17f, 0x17f], [0x212a, 0x212a], [0x2070, 0x209f], [0x2460, 0x24ff], [0x1d400, 0x1d7ff]]) {
  for (let cp = lo; cp <= hi; cp++) {
    const ch = String.fromCodePoint(cp);
    const folded = ch.normalize('NFKC');
    if (folded !== ch) COMPAT_FOLD.set(ch, folded);
  }
}
function foldCompatMatch(run) {
  if (run.charCodeAt(0) >= 0xff01 && run.charCodeAt(0) <= 0xff5e) {
    const parts = [];
    for (let i = 0; i < run.length; i += 4096) {
      const end = Math.min(run.length, i + 4096);
      const codes = new Array(end - i);
      for (let j = i; j < end; j++) codes[j - i] = run.charCodeAt(j) - 0xfee0;
      parts.push(String.fromCharCode.apply(null, codes));
    }
    return parts.join('');
  }
  return COMPAT_FOLD.get(run);
}
const ANSI_ESCAPE_RE = /\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07\x1b]*\x07/g;
const B64_EXEC_RE = /(?:echo|printf)\s+([A-Za-z0-9+/=]{16,})\s*\|\s*(?:base64\s+-(?:d|-decode)|openssl)/i;

// Maximal whitespace runs; only runs that contain a line break are joined.
// A pattern anchored on the line break (such as /[^\S\r\n]*[\r\n]/) would
// rescan a long run of spaces from every position.
const WHITESPACE_RUN_RE = /\s+/g;
const LINE_BREAK_RE = /[\r\n]/;
const JOIN_LEFT_RE = /[\p{L}\p{N}_<|/.-]/u;
const JOIN_RIGHT_RE = /[\p{L}\p{N}_>|/.-]/u;

// Removes /* ... */ comments in one pass. An unterminated "/*" ends the
// search: no later comment can be closed either.
function stripCComments(str) {
  let start = str.indexOf('/*');
  if (start === -1) return str;
  let out = '';
  let from = 0;
  while (start !== -1) {
    const end = str.indexOf('*/', start + 2);
    if (end === -1) break;
    out += str.slice(from, start);
    from = end + 2;
    start = str.indexOf('/*', from);
  }
  return out + str.slice(from);
}

// Removes invisible characters (zero-width, variation selectors, tag
// characters) for matching only; the caller's text is never changed.
function stripInvisible(str) {
  return str.replace(ZERO_WIDTH_RE, '').replace(INVISIBLE_ASTRAL_RE, '');
}

// Index map for a text with invisible characters removed: `clean` is the text
// without them and `map[i]` is the index in `text` of clean[i] (map[clean.length]
// is text.length). Returns null when the text has no invisible character. A
// match [s, e) in `clean` covers text [map[s], map[e - 1] + 1), which includes
// the invisible characters inside it.
function invisibleView(text) {
  const runs = [];
  for (const m of text.matchAll(ZERO_WIDTH_RE)) runs.push(m.index, m.index + m[0].length);
  for (const m of text.matchAll(INVISIBLE_ASTRAL_RE)) runs.push(m.index, m.index + m[0].length);
  if (runs.length === 0) return null;
  // The runs of both patterns are merged in index order.
  const sorted = [];
  for (let r = 0; r < runs.length; r += 2) sorted.push([runs[r], runs[r + 1]]);
  sorted.sort((a, b) => a[0] - b[0]);
  const clean = text.replace(ZERO_WIDTH_RE, '').replace(INVISIBLE_ASTRAL_RE, '');
  const map = new Int32Array(clean.length + 1);
  let c = 0;
  let pos = 0;
  for (const [start, end] of sorted) {
    for (let i = pos; i < start; i++) map[c++] = i;
    pos = end;
  }
  for (let i = pos; i < text.length; i++) map[c++] = i;
  map[c] = text.length;
  return { clean, map };
}

function normalizeInput(str) {
  if (typeof str !== 'string') return { normalized: '', stripped: '' };
  // 1. Strip invisible evasion characters (zero-width, variation selectors, tag characters)
  let stripped = stripInvisible(str);
  // 2. Strip ANSI escape sequences
  stripped = stripped.replace(ANSI_ESCAPE_RE, '');
  // 3. Strip inline C-style comments (e.g. sys/*safe*/tem -> system)
  stripped = stripCComments(stripped);
  // 4. Compatibility folding for matching: fullwidth Latin and other
  //    compatibility forms become their ASCII equivalents (NFKC).
  if (NON_ASCII_RE.test(stripped)) stripped = stripped.replace(COMPAT_FOLD_RE, foldCompatMatch);
  // 5. Rejoin words and tokens split across newlines (e.g. sys\ntem -> system, /l\neak -> /leak, Cyrillic & Chinese).
  //    Linear: only the character on each side of a newline run is inspected.
  if (LINE_BREAK_RE.test(stripped)) {
    stripped = stripped.replace(WHITESPACE_RUN_RE, (run, offset, whole) => {
      if (!LINE_BREAK_RE.test(run)) return run;
      const left = offset > 0 ? whole[offset - 1] : '';
      const right = whole[offset + run.length] || '';
      return left && right && JOIN_LEFT_RE.test(left) && JOIN_RIGHT_RE.test(right) ? '' : run;
    });
  }
  // 5. Normalize homoglyphs (Cyrillic to Latin for English hijack detection)
  let normalized = stripped.replace(/[\u0130\u0131\u0410-\u0456]/g, (m) => HOMOGLYPH_MAP[m] || m);
  return { normalized, stripped };
}

// evaluate() analyses inputs longer than MAX_SCAN_CHARS as head + tail and
// marks the result `truncated: true`. Tool results are scanned in overlapping
// windows (up to MAX_TOOL_RESULT_SCAN_CHARS) by scanWindows() below.
const MAX_SCAN_CHARS = 256 * 1024;
const SCAN_HEAD_CHARS = 192 * 1024;
// One character is reserved for the separator, so the window fits the limit.
const SCAN_TAIL_CHARS = MAX_SCAN_CHARS - SCAN_HEAD_CHARS - 1;

function evaluateUncached(input, options = {}) {
  if (typeof input !== 'string') {
    return { verdict: 'allow', confidence: 1.0, rule: 'none', reason: null, engine: 'oss-local', rules_version: RULES_VERSION };
  }
  if (input.length > MAX_SCAN_CHARS) {
    // NUL is neither whitespace nor a word character, so normalization cannot
    // join the end of the head and the start of the tail into a new token.
    const window = input.slice(0, SCAN_HEAD_CHARS) + '\u0000' + input.slice(-SCAN_TAIL_CHARS);
    return { ...evaluateUncached(window, options), truncated: true };
  }

  // Pre-normalization passes: stripped (preserves non-Latin) and normalized (maps homoglyphs)
  const { normalized, stripped } = normalizeInput(input);

  const strict = strictMode(options, loadCustomConfig());
  let tierAdvisory = null;

  // Check Base64 payload smuggling
  let b64Advisory = null;
  const b64Match = normalized.match(B64_EXEC_RE) || stripped.match(B64_EXEC_RE);
  if (b64Match && b64Match[1]) {
    try {
      const decoded = Buffer.from(b64Match[1], 'base64').toString('utf8');
      const innerRes = evaluate(decoded, options);
      if (innerRes.advisory) b64Advisory = innerRes.advisory;
      if (innerRes.verdict === 'block') {
        return {
          ...innerRes,
          reason: `Smuggled Base64 execution: ${innerRes.reason || innerRes.rule}`,
          rule: 'evasion:base64_smuggling',
        };
      }
    } catch (e) {
      // ignore invalid base64
    }
  }

  // Check against normalized, stripped, and raw input
  const targets = Array.from(new Set([normalized, stripped, input]));

  for (const text of targets) {
    // 0. Evasion Rules (BiDi Trojan Source)
    for (const rule of EVASION_RULES) {
      if (rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.99, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 1. Covert Markdown Image Exfiltration
    for (const rule of MARKDOWN_EXFIL_RULES) {
      if (rule.test ? rule.test(text) : rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.98, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 2. Sensitive Path Traversal / Credential File Access
    for (const rule of SENSITIVE_PATH_RULES) {
      if (rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.92, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 3. Indirect Injection Rules (HTML comments / hidden elements)
    for (const rule of INDIRECT_INJECTION_RULES) {
      if (rule.test ? rule.test(text) : rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.95, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 4. Standard Prompt Injection Rules
    for (const rule of INJECTION_RULES) {
      if (rule.test ? rule.test(text) : rule.pattern.test(text)) {
        if (!strict && ADVISORY_BY_DEFAULT.has(rule.id)) {
          if (!tierAdvisory) tierAdvisory = { rule: rule.id, reason: rule.description };
          continue;
        }
        return { verdict: 'block', confidence: 0.95, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 5. Exfiltration Rules
    for (const rule of EXFIL_RULES) {
      if (rule.compound.every((re) => re.test(text))) {
        return { verdict: 'block', confidence: 0.9, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }
  }

  // 6. Project-specific Custom Rules (.znrules / zn.config.json)
  const cfg = loadCustomConfig();
  for (const pat of cfg.bannedPatterns) {
    if (pat.test(input)) {
      return { verdict: 'block', confidence: 1.0, reason: `Matches custom repository rule: ${pat.source}`, rule: 'custom:banned_pattern', engine: 'oss-local', rules_version: RULES_VERSION };
    }
  }
  for (const fpath of cfg.forbiddenPaths) {
    if (input.includes(fpath)) {
      return { verdict: 'block', confidence: 1.0, reason: `Matches custom repository forbidden path: ${fpath}`, rule: 'custom:forbidden_path', engine: 'oss-local', rules_version: RULES_VERSION };
    }
  }

  if (tierAdvisory) {
    return {
      verdict: 'allow', confidence: 0.99, rule: 'none', reason: null, engine: 'oss-local', rules_version: RULES_VERSION,
      advisory: tierAdvisory,
    };
  }

  for (const text of targets) {
    for (const rule of ADVISORY_RULES) {
      if (matchesRule(rule, text)) {
        return {
          verdict: 'allow', confidence: 0.99, rule: 'none', reason: null, engine: 'oss-local', rules_version: RULES_VERSION,
          advisory: { rule: rule.id, reason: rule.description },
        };
      }
    }
  }

  if (b64Advisory) {
    return {
      verdict: 'allow', confidence: 0.99, rule: 'none', reason: null, engine: 'oss-local', rules_version: RULES_VERSION,
      advisory: { ...b64Advisory },
    };
  }

  return { verdict: 'allow', confidence: 0.99, rule: 'none', reason: null, engine: 'oss-local', rules_version: RULES_VERSION };
}

// -------------------------------------------------------------------------
// DLP & Secret Masking Rules
// -------------------------------------------------------------------------
// A text without one of these cannot match the credential patterns, which are
// then not run at all.
const ENV_CREDENTIAL_PREFILTER = /_[Kk][Ee][Yy]|_[Tt][Oo][Kk][Ee][Nn]|_[Pp][Aa][Ss][Ss]/;
const PREFIXED_CREDENTIAL_PREFILTER = /KEY|TOKEN|SECRET|PASS|PWD|CREDENTIALS/;

const SECRET_PATTERNS = [
  // A body may not contain another BEGIN header: linear on repeated headers without END.
  { id: 'secret:private_key', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----(?:(?!-----BEGIN )[\s\S])*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: '[REDACTED_PRIVATE_KEY]' },
  { id: 'secret:anthropic_key', pattern: /(?<![A-Za-z0-9_])(sk-ant-[A-Za-z0-9_-]{30,})(?:(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]))/g, replacement: '[REDACTED_ANTHROPIC_KEY]' },
  // A key without a known prefix ends at the first character that is not a letter or digit.
  { id: 'secret:openai_key', pattern: /(?<![A-Za-z0-9_])(sk-(?:(?:proj|svcacct|admin|[Nn]one|or-v1|lf)-[A-Za-z0-9_-]{28,}(?:(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]))|helicone-(?:(?:eu|cp|gov|rl)-){0,4}[a-z0-9]{7}(?:-[a-z0-9]{7}){3}(?![a-z0-9])|(?=(?:eu|cp|gov|rl)-|[a-z0-9]{7}-)(?=[a-z-]{0,46}[0-9])(?:(?:eu|cp|gov|rl)-){0,4}[a-z0-9]{7}(?:-[a-z0-9]{7}){3}(?![a-z0-9])(?!-[a-z0-9])|sp-[A-Za-z0-9]{28,}(?![A-Za-z0-9])|[A-Za-z0-9]{28,}(?![A-Za-z0-9])|(?:(?!sk-)[A-Za-z0-9_-]){1,200}?T3BlbkFJ[A-Za-z0-9_-]{20,}(?:(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]))))/g, replacement: '[REDACTED_OPENAI_KEY]' },
  { id: 'secret:aws_access_key', pattern: /(?<![A-Za-z0-9_])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9_])/g, replacement: '[REDACTED_AWS_KEY]' },
  { id: 'secret:aws_secret_key', pattern: /((?:[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy]|[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]|[Aa][Ww][Ss]_[Kk][Ee][Yy])\s*[:=]\s*['"]?)([A-Za-z0-9/+=]{40})(['"]?)/g, replacement: '$1[REDACTED_AWS_SECRET]$3' },
  { id: 'secret:github_token', pattern: /(?<![A-Za-z0-9_])((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{82})(?![A-Za-z0-9_])/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { id: 'secret:db_url_password', pattern: /((?:[Pp][Oo][Ss][Tt][Gg][Rr][Ee][Ss](?:[Qq][Ll])?|[Mm][Yy][Ss][Qq][Ll]|[Mm][Oo][Nn][Gg][Oo][Dd][Bb](?:\+[Ss][Rr][Vv])?|[Rr][Ee][Dd][Ii][Ss]|[Aa][Mm][Qq][Pp]):\/\/[^:\s\/]+:)(?!(?:\$\{(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*)\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_][A-Z0-9_]*%|<[A-Za-z][A-Za-z_-]{0,63}>|\{\{\s*[A-Za-z_][A-Za-z_.]*\s*\}\})@)([^@\s\/]+)(@)/g, replacement: '$1[REDACTED_DB_PASSWORD]$3' },
  // The lookahead + backreference pairs act as atomic groups, so a long run of
  // "-eyJ" cannot make the engine retry every split point, and the lookbehind
  // allows a single start per token. Only used when the
  // text contains ".eyJ" (see redactSecrets).
  { id: 'secret:jwt_token', pattern: /(?<![A-Za-z0-9_-])(eyJ(?=([A-Za-z0-9_-]{10,512}))\2\.eyJ(?=([A-Za-z0-9_=-]{10,8192}))\3\.[A-Za-z0-9_.+/=-]{10,4096})(?:(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]))/g, replacement: '[REDACTED_JWT]', requires: '.eyJ' },
  // Credential assignments. A name right after "${" is a shell reference, and
  // after "$" (PHP, PowerShell, Perl) only "=" assigns: "$NAME:" is a reference
  // followed by text. The value (group 2) is checked with isNonSecretValue. The
  // u flag makes the 12-character minimum count code points, as in Python.
  { id: 'secret:env_credential', pattern: /(?=[A-Za-z0-9_])(?<![A-Za-z0-9_])(?<!\$\{)(?:(?<!\$)|(?=[A-Za-z0-9_]+\s*=))((?:[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]_[Kk][Ee][Yy]|[Aa][Pp][Ii]_[Kk][Ee][Yy]|[Aa][Uu][Tt][Hh]_[Tt][Oo][Kk][Ee][Nn]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee]_[Kk][Ee][Yy]|[Dd][Aa][Tt][Aa][Bb][Aa][Ss][Ee]_[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd])["']?\s*[:=]\s*['"]?)([^\s'"]{12,})(['"]?)/gu, replacement: '$1[REDACTED_SECRET]$3', valueFilter: isNonSecretValue, prefilter: ENV_CREDENTIAL_PREFILTER },
  // Environment-style names with a prefix: OPENAI_API_KEY=, "DB_PASSWORD": "...",
  // `ENV X_TOKEN value` in a Dockerfile, $X_SECRET = '...' in PHP. Upper case
  // only, so code such as `token = response.json()` is left alone.
  { id: 'secret:prefixed_credential', pattern: /(?=[A-Z0-9])(?<![A-Za-z0-9_])(?<!\$\{)(?:(?<!\$)|(?=[A-Za-z0-9_]+[ \t]*=))((?:ENV[ \t]+(?:[A-Z0-9]+_)+(?:API_KEY|APIKEY|SECRET_ACCESS_KEY|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CREDENTIALS|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD)[ \t]+|(?:[A-Z0-9]+_)+(?:API_KEY|APIKEY|SECRET_ACCESS_KEY|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CREDENTIALS|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD)["']?[ \t]*[:=][ \t]*)['"]?)([^\s'"]{12,})(['"]?)/gu, replacement: '$1[REDACTED_SECRET]$3', valueFilter: isNonSecretValue, prefilter: PREFIXED_CREDENTIAL_PREFILTER },
  // The default of a shell or Compose reference, ${DB_PASSWORD:-<value>}: only
  // redacted when it looks machine-generated (most defaults are for development).
  { id: 'secret:credential_default', pattern: /(\$\{(?:[A-Z0-9]+_)*(?:API_KEY|APIKEY|SECRET_ACCESS_KEY|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CREDENTIALS|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD):?[-=])([^\s'"{}$]{12,})(\})/gu, replacement: '$1[REDACTED_SECRET]$3', valueFilter: isNonSecretDefault, requires: '${' },
];

// Extra credential forms that only `zn-gate scan` reports (files at rest, not
// agent traffic). They run after SECRET_PATTERNS, on the text those already
// redacted, so a value found by both is reported once.
//   secret:cli_credential_flag   --api-key=..., --password=..., --token=... on
//     a command line. A flag without a value, a reference ($TOKEN, ${X}) or a
//     placeholder (<token>, changeme) is left alone.
//   secret:credential_assignment a quoted value assigned to a name that ends
//     in password, passwd, secret, token or api key, in lower or mixed case,
//     with =, :, := or => (also $name = "..." in PHP, Perl and PowerShell).
//     Only values that look machine-generated count, so labels and messages
//     (i18n files, "password": "Contraseña") are not reported.
const SCAN_FLAG_PREFILTER = /--(?:api|pass|token|secret|access|auth|client)/;
const SCAN_ASSIGNMENT_PREFILTER = /[Pp][Aa][Ss][Ss][Ww]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Kk][Ee][Yy]/;
const SCAN_SECRET_PATTERNS = [
  { id: 'secret:cli_credential_flag', pattern: /(?<![A-Za-z0-9_-])(--(?:api[-_]?key|password|passwd|token|secret|access[-_]token|auth[-_]token|client[-_]secret)=["']?)([^\s'"]{8,512})[^\s'"]*(["']?)/gu, replacement: '$1[REDACTED_SECRET]$3', valueFilter: isNonSecretValue, prefilter: SCAN_FLAG_PREFILTER },
  // The name is at most 40 characters before the keyword, so each start costs a bounded amount.
  { id: 'secret:credential_assignment', pattern: /(?<![A-Za-z0-9_$])(\$?[A-Za-z0-9_]{0,40}?(?:[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy])["']?[ \t]*(?::=|=>|=|:)[ \t]*["'])([^\s'"]{8,512})(["'])/gu, replacement: '$1[REDACTED_SECRET]$3', valueFilter: isNonSecretDefault, prefilter: SCAN_ASSIGNMENT_PREFILTER },
];

// ---------------------------------------------------------------------------
// Values of credential assignments that are not secrets. The checks run in
// this order:
// 1. Longer than MAX_FILTERED_VALUE: a secret (keeps the checks linear).
// 2. References: already redacted, URLs without a password in the user info,
//    secret-manager references (ARN, vault:, Key Vault, projects/*/secrets/*),
//    code that reads the environment or settings (process.env., os.environ,
//    getenv(, settings., secrets., std::env::...), and a placeholder or
//    template that is the whole value (${VAR}, $VAR, <...>, {{...}}, ***).
// 3. Names and code: file names with a known extension, host names, calls
//    and indexes that start with an identifier, identifier chains (a.b, a::b,
//    a->b) and constant or snake_case names. A chain or name is not code when
//    a part of it looks random, so a Mapbox sk.eyJ... or SendGrid SG.x.y key
//    is still a secret. Paths, unless a segment looks random (a base64 key
//    may start with "/").
// 4. A placeholder mark inside the value (xxxx, ***, <...>, ${, a leading
//    "<", "{" or "["): not a secret, unless the value looks machine-generated.
// 5. Placeholder words (your-key-here, changeme, fake, mock, test...), unless
//    the value is long and random.
// 6. A value that looks machine-generated is a secret.
// 7. A value made only of letters is not a secret when one of its words
//    describes it (MySecretKey, api-token-here, ask-the-ops-team); short
//    lower-case slugs name an object (regcred-ghcr, ingress-nginx-tls).
// Everything else, including lower-case passphrases joined by "-", is a secret.
// ---------------------------------------------------------------------------
const MAX_FILTERED_VALUE = 512;
// Characters of values checked per redactSecrets call (UTF-16 units). Past
// that, credential matches are redacted without the checks, which bounds
// their cost on crafted input.
const MAX_FILTERED_CHARS = 32 * 1024;
const CREDENTIAL_URL_RE = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/(?:[^\/@:\s]*:([^\/@\s]*)@)?/;
const CREDENTIAL_STORE_RE = /^(?:arn:|vault:|secretref:|@Microsoft\.KeyVault\(|projects\/[^\/]+\/secrets\/)/;
const CREDENTIAL_CODE_ROOT_RE = /^(?:process\.env[.\[]|import\.meta\.env[.\[]|os\.environ|os\.getenv\(|getenv\(|settings\.|config\.|secrets\.|std::env::|env::var|ENV(?:\[|\.fetch\()|\$ENV\{|System\.getenv\(|Deno\.env\.|Bun\.env\.|\[Environment\]::|\([A-Z][a-z]+-[A-Z])/;
// A placeholder or reference that is the whole value (always left alone).
const CREDENTIAL_PLACEHOLDER_RE = /^(?:%\([A-Za-z_]*\)s|<[^<>]*>|\{\{[^{}]*\}\}|\$\{[^{}]*\}|#\{[^{}]*\}|\*+|!(?:Ref|Sub|GetAtt|ImportValue|Join|Select|Split|FindInMap|If|Base64|Cidr|GetAZs|Equals|And|Or|Not|Condition|Transform)|([A-Za-z0-9])(?:\1|[-_.:])*)$/;
// A variable or template reference that is the whole value ($VAR, $$VAR,
// $env:VAR, %VAR%, @name@, [name]): left alone unless the part inside looks random.
// The part inside must read as a name: UPPER_CASE, lower.case or camelCase words.
const CREDENTIAL_REFERENCE_NAME_RE = /^(?:[A-Z][A-Z0-9_]*|[a-z][a-z0-9_.-]*|[A-Za-z][a-z]+(?:[A-Z][a-z]+)*[0-9]*)$/;
const CREDENTIAL_REFERENCE_RE = /^(?:\$\$?([A-Za-z_][A-Za-z0-9_]*)|\$env:([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%|@([A-Za-z0-9_.-]+)@|\[([^\[\]]*)\])$/;
// Placeholder marks inside a value: left alone unless the value looks
// machine-generated (a password manager may produce `<`, `{{` or `***`).
const CREDENTIAL_PLACEHOLDER_MARK_RE = /<[^<>]*>|^[<{\[]|^\$\(|^(?:0123456789|1234567890|[Aa][Bb][Cc][Dd][Ee][Ff]|[Qq][Ww][Ee][Rr][Tt][Yy])|([A-Za-z0-9])\1{7,}/;
const CREDENTIAL_PLACEHOLDER_MARKS = ['xxxx', '***', '...', '${', '#{', '{{', 'deadbeef'];
const CREDENTIAL_PLACEHOLDER_WORDS = /(?<![A-Za-z])(?:password|passwd|passw0rd|secret|changeme|change_me|example|placeholder|your[_-]?|redacted|dummy|sample|foobar|hunter2|todo|insert|replace|mypass|pass(?:word)?123|fake|mock|tests?|testing|demo|stub|fixme|not[_-]?set|unset|set[_-]me|change[_-]this)(?![A-Za-z])/i;
const CREDENTIAL_CODE_RE = /^[(!&*@:]*([A-Za-z_$][A-Za-z0-9_$]*(?:(?:\?\.|\.|::|->)[A-Za-z_$][A-Za-z0-9_$]*)*)(?:((?:->[(\[{]|!?[(\[])(?:[A-Za-z0-9_$.:=(\[{!?&|,]|[)\]}](?![A-Za-z0-9_$]))*)|!|[)\]]*)$/;
const CREDENTIAL_DOTTED_WORDS_RE = /^[a-z]+(?:\.[a-z]+){2,}$/;
const CREDENTIAL_IDENTIFIER_RE = /^(?:_*[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+_*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[A-Z]+)$/;
const CREDENTIAL_PATH_RE = /^(?:(?:~|\.{1,2})?\/|[A-Za-z]:[\\\/]|\\\\)[^+=]*$|^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+$/;
const CREDENTIAL_FILE_EXT_RE = /\.[A-Za-z][A-Za-z0-9]{0,4}$/;
const CREDENTIAL_FILE_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:json|ya?ml|pem|p8|p12|pfx|key|keystore|jks|crt|cer|der|txt|ini|toml|conf|cfg|xml|properties|env|gpg|asc|ppk|pub|kdbx)$/;
const CREDENTIAL_HOST_NAME_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)*\.(?:com|net|org|io|dev|app|cloud|internal|local|svc|co|ai|sh)$/;
const CREDENTIAL_SLUG_RE = /^[a-z0-9]+(?:[-.][a-z0-9]+)+$/;
const CREDENTIAL_SLUG_SHORT_WORD_RE = /(?:^|[-.])(?:[a-z0-9]{1,3}|[a-z]*[0-9][a-z0-9]*)(?:[-.]|$)/;
const CREDENTIAL_OBJECT_NAME_RE = /_(?:SECRET|CREDENTIALS)(?![A-Za-z0-9_])/;
const CREDENTIAL_LETTERS_RE = /^[A-Za-z]+(?:[-_.][A-Za-z]+)*$/;
const CREDENTIAL_DESCRIPTIVE_WORDS = /(?:^|-)(?:keys?|tokens?|secrets?|pass|passwords?|passwd|pwd|api|apikey|auth|credentials?|access|private|here|value|string|my|your|default|dev|development|local|prod|production|staging|none|null|empty|required|some|generated|random|change|replace|set|use|put|enter|fill|ask|get|see|from|the|not|check|contact|generate|read|find|fake|mock|tests?|dummy|example|sample|placeholder|todo)(?:-|$)|secret|passw|token|apikey|changeme|example|placeholder|dummy/;
const CREDENTIAL_HEX_RE = /^[0-9A-Fa-f]{32,}$/;
const WORD_TOKEN_RE = /[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+/g;

function trimSeparators(value) {
  let end = value.length;
  while (end > 0 && (value[end - 1] === ';' || value[end - 1] === ',')) end--;
  return value.slice(0, end);
}

// Shannon entropy per character, length counted in UTF-16 units. Characters
// are summed in order of first appearance, as in the Python port.
const ASCII_COUNTS = new Int32Array(128);
function entropy(s) {
  if (/^[\x00-\x7f]*$/.test(s)) {
    const order = [];
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (ASCII_COUNTS[c]++ === 0) order.push(c);
    }
    let h = 0;
    for (const c of order) {
      const p = ASCII_COUNTS[c] / s.length;
      h -= p * Math.log2(p);
      ASCII_COUNTS[c] = 0;
    }
    return h;
  }
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// A digit, three character classes and at least 3 bits per character.
// Without a digit: 16 or more characters with upper case, lower case and
// symbols, at least 3.5 bits per character and no word structure (passwords
// from a password manager).
function looksMachineGenerated(v) {
  const digit = /[0-9]/.test(v);
  const classes = (/[a-z]/.test(v) ? 1 : 0) + (/[A-Z]/.test(v) ? 1 : 0) + (digit ? 1 : 0) + (/[^A-Za-z0-9]/.test(v) ? 1 : 0);
  if (classes < 3) return false;
  if (digit) return entropy(v) >= 3.0;
  return v.length >= 16 && entropy(v) >= 3.5 && machineLikePart(v);
}

// Text that reads as random rather than as words: ten or more letters and
// digits with fewer than 2.5 per word (camelCase humps, upper-case runs and
// numbers count as words), or twenty or more that mix upper case, lower case
// and digits.
function machineLikePart(s) {
  if (s.length < 10) return false;
  const alnum = s.replace(/[^A-Za-z0-9]/g, '').length;
  if (alnum < 10) return false;
  if (alnum >= 20 && /[0-9]/.test(s) && /[a-z]/.test(s) && /[A-Z]/.test(s)) return true;
  const words = (s.match(WORD_TOKEN_RE) || []).length;
  return alnum * 2 < words * 5;
}

// A call or index (getenv(, os.environ[, z.string().min(1)) is code. A chain
// without one (settings.X, var.name, @user.key) and a constant or snake_case
// name are code unless a part looks random. Three or more lower-case words
// joined by "." are a passphrase, not a chain.
function looksLikeCode(v) {
  const m = CREDENTIAL_CODE_RE.exec(v);
  if (m && m[2] !== undefined) return !m[1].split(/\?\.|\.|::|->/).some(machineLikePart);
  if (CREDENTIAL_DOTTED_WORDS_RE.test(v)) return false;
  if (m && /\.|::|->/.test(m[1])) return !m[1].split(/\?\.|\.|::|->/).some(machineLikePart);
  return CREDENTIAL_IDENTIFIER_RE.test(v) && !v.split('_').some(machineLikePart);
}

// Absolute paths, and relative ones that end with a file extension.
function looksLikePath(v) {
  if (!CREDENTIAL_PATH_RE.test(v)) return false;
  if (!/^[~.\/\\]|^[A-Za-z]:/.test(v) && !CREDENTIAL_FILE_EXT_RE.test(v)) return false;
  return !v.split(/[\\\/]/).some(machineLikePart);
}

function asciiLower(s) {
  return s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

// A placeholder mark inside the value; lv is v with ASCII letters lower-cased.
function placeholderMark(v, lv) {
  return CREDENTIAL_PLACEHOLDER_MARK_RE.test(v) || CREDENTIAL_PLACEHOLDER_MARKS.some((m) => lv.includes(m));
}

function isReference(v) {
  const m = CREDENTIAL_REFERENCE_RE.exec(v);
  if (!m) return false;
  const inner = m.slice(1).find((g) => g !== undefined);
  if (!CREDENTIAL_REFERENCE_NAME_RE.test(inner)) return false;
  return !(looksMachineGenerated(inner) || inner.split(/[-_.]/).some(machineLikePart));
}

function isPlaceholderValue(v) {
  return CREDENTIAL_PLACEHOLDER_RE.test(v) || isReference(v) || placeholderMark(v, asciiLower(v)) || CREDENTIAL_PLACEHOLDER_WORDS.test(v);
}

// A file name with a known extension, or a host name.
function looksLikeName(v) {
  return (CREDENTIAL_FILE_NAME_RE.test(v) && !machineLikePart(v)) || CREDENTIAL_HOST_NAME_RE.test(v);
}

// Lower-case words joined by "-" or "." that name an object rather than hold
// a passphrase: two words, three words with a short or numbered word, three
// words under a *_SECRET or *_CREDENTIALS name (Kubernetes secrets, pull
// secrets, credential files), or any number of words under such a name when
// one is short or numbered (cert-manager-webhook-ca).
function looksLikeSlug(v, prefix) {
  if (!CREDENTIAL_SLUG_RE.test(v)) return false;
  const words = v.split(/[-.]/).length;
  if (words <= 2) return true;
  const shortWord = CREDENTIAL_SLUG_SHORT_WORD_RE.test(v);
  const objectName = CREDENTIAL_OBJECT_NAME_RE.test(prefix);
  return (words === 3 && (shortWord || (objectName && !v.includes('.')))) || (objectName && shortWord);
}

// Only letters, and one of the words says what the value is or is for.
function describesItself(v) {
  if (!CREDENTIAL_LETTERS_RE.test(v)) return false;
  return CREDENTIAL_DESCRIPTIVE_WORDS.test((v.match(WORD_TOKEN_RE) || []).join('-').toLowerCase());
}

const NOT_SECRET = 0;
const SECRET = 1;
const GENERATED_SECRET = 2;

function credentialValueKind(value, prefix) {
  if (value.length > MAX_FILTERED_VALUE) return GENERATED_SECRET;
  const v = trimSeparators(value);
  if (!v || v.includes('[REDACTED_')) return NOT_SECRET;
  const url = CREDENTIAL_URL_RE.exec(v);
  if (url) {
    const pwd = url[1];
    return pwd === undefined || pwd === '' || /^[$%<{]/.test(pwd) || isPlaceholderValue(pwd) ? NOT_SECRET : GENERATED_SECRET;
  }
  if (CREDENTIAL_STORE_RE.test(v) || CREDENTIAL_CODE_ROOT_RE.test(v) || CREDENTIAL_PLACEHOLDER_RE.test(v) || isReference(v)) return NOT_SECRET;
  if (looksLikeName(v) || looksLikeCode(v) || looksLikePath(v)) return NOT_SECRET;
  const generated = looksMachineGenerated(v);
  // A whole-value reference shape with a random inside ([...], $..., @...@) is not a placeholder.
  if (!CREDENTIAL_REFERENCE_RE.test(v) && placeholderMark(v, asciiLower(v))) return generated ? GENERATED_SECRET : NOT_SECRET;
  if (CREDENTIAL_PLACEHOLDER_WORDS.test(v)) return generated && v.length >= 24 && machineLikePart(v) ? GENERATED_SECRET : NOT_SECRET;
  if (generated) return GENERATED_SECRET;
  if (describesItself(v) || looksLikeSlug(v, prefix)) return NOT_SECRET;
  return CREDENTIAL_HEX_RE.test(v) && /[0-9]/.test(v) && /[A-Fa-f]/.test(v) ? GENERATED_SECRET : SECRET;
}

function isNonSecretValue(value, prefix = '') {
  return credentialValueKind(value, prefix) === NOT_SECRET;
}

// Defaults are only redacted when they look machine-generated.
function isNonSecretDefault(value, prefix = '') {
  return credentialValueKind(value, prefix) !== GENERATED_SECRET;
}

// Replacement template with $1..$9 expanded from the groups of a match. A group
// is a [start, end] span of the original text, or null when it did not take part;
// the text kept around a secret is copied from the original, invisible characters
// included.
function expandTemplate(template, groups, text) {
  return template.replace(/\$(\d)/g, (_, d) => {
    const g = groups[Number(d)];
    return g ? text.slice(g[0], g[1]) : '';
  });
}

// Span [start, end) of a text without invisible characters, as a span of the
// original text. `map` is null for the original text itself.
function spanIn(map, start, end) {
  if (!map) return [start, end];
  return [map[start], end > start ? map[end - 1] + 1 : map[start]];
}

// Candidate redactions of one rule, pushed to `out` as {start, end, rule, text}
// in original coordinates. The rule runs on the original text and, when the text
// has invisible characters, on the text without them, so a secret is found when
// either run finds it: "AKIA" + 16 characters + zero-width space + "foo" is found
// on the original text, and "AKIA" + zero-width space + 16 characters on the view.
function ruleCandidates(item, text, view, budget, out) {
  const passes = view ? [[text, null], [view.clean, view.map]] : [[text, null]];
  const flags = item.pattern.flags.includes('d') ? item.pattern.flags : item.pattern.flags + 'd';
  const regex = new RegExp(item.pattern.source, flags);
  for (const [hay, map] of passes) {
    if (item.requires && !hay.includes(item.requires)) continue;
    if (item.prefilter && !item.prefilter.test(hay)) continue;
    regex.lastIndex = 0;
    let m;
    while ((m = regex.exec(hay)) !== null) {
      if (m[0].length === 0) {
        regex.lastIndex++;
        continue;
      }
      const groups = [null];
      for (let k = 1; k < m.length; k++) {
        groups.push(m.indices[k] ? spanIn(map, m.indices[k][0], m.indices[k][1]) : null);
      }
      if (item.valueFilter) {
        // The value (group 2) decides whether the match is redacted.
        const value = stripInvisible(text.slice(groups[2][0], groups[2][1]));
        const prefix = groups[1] ? stripInvisible(text.slice(groups[1][0], groups[1][1])) : '';
        const n = value.length;
        if (n <= MAX_FILTERED_VALUE && n <= budget.left) {
          budget.left -= n;
          if (item.valueFilter(value, prefix)) continue;
        }
      }
      const [start, end] = spanIn(map, m.index, m.index + m[0].length);
      out.push({ start, end, rule: item.id, text: expandTemplate(item.replacement, groups, text) });
    }
  }
}

// Overlapping candidates become one redaction covering their union. The first
// candidate (earliest start, then longest) supplies the replacement text.
function mergeCandidates(cands) {
  cands.sort((a, b) => a.start - b.start || b.end - a.end);
  const merged = [];
  for (const c of cands) {
    const last = merged[merged.length - 1];
    if (last && c.start < last.end) {
      if (c.end > last.end) last.end = c.end;
      continue;
    }
    merged.push({ ...c });
  }
  return merged;
}

// Redacts secrets. Every rule runs on the original text and on the text without
// invisible characters (see ruleCandidates), and the redacted spans are the union
// of what both find, so a secret split by a zero-width or tag character is
// redacted whole. Texts without invisible characters are handled as before.
function redactSecrets(text) {
  return redactWith(text, SECRET_PATTERNS);
}

// SCAN_SECRET_PATTERNS alone (`zn-gate scan` runs them last, on text that
// the other rules and the scrubber already redacted).
function redactScanRules(text) {
  return redactWith(text, SCAN_SECRET_PATTERNS);
}

// redactSecrets plus SCAN_SECRET_PATTERNS, for the lines `zn-gate scan` prints.
function redactScanSecrets(text) {
  const first = redactWith(text, SECRET_PATTERNS);
  const second = redactWith(first.sanitized, SCAN_SECRET_PATTERNS);
  return { sanitized: second.sanitized, detections: first.detections.concat(second.detections) };
}

function redactWith(text, patterns) {
  if (typeof text !== 'string' || !text) {
    return { sanitized: text, detections: [] };
  }
  let sanitized = text;
  const detections = [];
  const budget = { left: MAX_FILTERED_CHARS };
  let view = null;
  let dirty = true;
  for (const item of patterns) {
    if (dirty) {
      view = invisibleView(sanitized);
      dirty = false;
    }
    const cands = [];
    ruleCandidates(item, sanitized, view, budget, cands);
    if (cands.length === 0) continue;
    let out = '';
    let last = 0;
    for (const e of mergeCandidates(cands)) {
      out += sanitized.slice(last, e.start) + e.text;
      last = e.end;
      detections.push({ rule: e.rule, index: e.start });
    }
    sanitized = out + sanitized.slice(last);
    dirty = true;
  }
  return { sanitized, detections };
}

// Tool output can be large (file reads, search results). Instead of the
// head + tail view used by evaluate(), it is scanned in windows of
// MAX_SCAN_CHARS that overlap by SCAN_WINDOW_OVERLAP, so a payload in the
// middle is not skipped. Past MAX_TOOL_RESULT_SCAN_CHARS only the last window
// is added and the result is marked `truncated: true`. A match that spans more
// than SCAN_WINDOW_OVERLAP characters across a window boundary can be missed.
const SCAN_WINDOW_OVERLAP = 4 * 1024;
const MAX_TOOL_RESULT_SCAN_CHARS = 4 * 1024 * 1024;

function scanWindows(text, options = {}) {
  if (typeof text !== 'string' || text.length <= MAX_SCAN_CHARS) return evaluate(text, options);
  const step = MAX_SCAN_CHARS - SCAN_WINDOW_OVERLAP;
  const limit = Math.min(text.length, MAX_TOOL_RESULT_SCAN_CHARS);
  let res = null;
  let advisory = null;
  for (let start = 0; ; start += step) {
    const end = Math.min(start + MAX_SCAN_CHARS, limit);
    res = evaluateUncached(text.slice(start, end), options);
    if (!advisory && res.advisory) advisory = res.advisory;
    if (res.verdict === 'block' || end >= limit) break;
  }
  if (res.verdict !== 'block' && text.length > limit) {
    res = evaluateUncached(text.slice(-MAX_SCAN_CHARS), options);
    if (!advisory && res.advisory) advisory = res.advisory;
  }
  res = { ...res };
  if (res.verdict !== 'block' && advisory) res.advisory = { ...advisory };
  delete res.truncated;
  if (text.length > limit) res.truncated = true;
  return res;
}

function sanitizeToolResult(toolOrResult, content, options = {}) {
  if (content !== undefined && content !== null) {
    const toolName = String(toolOrResult);
    const textContent = typeof content === 'string' ? content : JSON.stringify(content);
    const assessment = scanWindows(textContent, options);
    const truncated = assessment.truncated === true;
    // Output too large to scan in full is allowed (with `truncated: true`)
    // unless the caller opts into blocking it.
    const blockTruncated = options.blockTruncated === true || process.env.ZN_BLOCK_TRUNCATED === '1';
    if (truncated && blockTruncated && assessment.verdict !== 'block') {
      assessment.verdict = 'block';
      assessment.confidence = 1.0;
      assessment.rule = 'size:truncated';
      assessment.reason = 'Output too large to scan in full';
    }
    const isBlock = assessment.verdict?.toLowerCase() === 'block';

    let sanitized = textContent;
    let secretsRedacted = 0;

    if (isBlock) {
      sanitized = `[REDACTED BY ZN-GATE: Malicious prompt injection payload detected in ${toolName} output (${assessment.reason || assessment.rule})]`;
    } else if (options.maskSecrets !== false) {
      const res = redactSecrets(textContent);
      sanitized = res.sanitized;
      secretsRedacted = res.detections.length;
    }

    return {
      tool_name: toolName,
      safe_to_ingest: !isBlock,
      truncated,
      assessment,
      secrets_redacted: secretsRedacted,
      sanitized_content: sanitized,
    };
  }

  // Deep sanitization of objects/arrays
  const detections = [];
  function _sanitize(val) {
    if (typeof val === 'string') {
      const res = redactSecrets(val);
      if (res.detections.length > 0) {
        detections.push(...res.detections);
      }
      return res.sanitized;
    } else if (Array.isArray(val)) {
      return val.map(_sanitize);
    } else if (val !== null && typeof val === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        out[k] = _sanitize(v);
      }
      return out;
    }
    return val;
  }

  const sanitized = _sanitize(toolOrResult);
  return { sanitized, detections };
}

// LRU cache for evaluate(): max 2048 entries keyed on raw input, only for
// inputs up to 8 KB so the cache itself stays small.
// Invalidated when RULES_VERSION changes or custom config reloads.
const EVAL_CACHE_MAX = 2048;
const EVAL_CACHE_MAX_INPUT = 8 * 1024;
const evalCache = new Map();
function evaluate(input, options = {}) {
  if (typeof input !== 'string' || input.length > EVAL_CACHE_MAX_INPUT) return evaluateUncached(input, options);
  const cfg = loadCustomConfig();
  const strict = strictMode(options, cfg);
  const hit = evalCache.get(input);
  if (hit !== undefined && hit.ver === RULES_VERSION && hit.cfg === cfg && hit.strict === strict) {
    evalCache.delete(input);
    evalCache.set(input, hit);
    return copyResult(hit.res);
  }
  const res = evaluateUncached(input, options);
  evalCache.set(input, { res, cfg, strict, ver: RULES_VERSION });
  if (evalCache.size > EVAL_CACHE_MAX) {
    evalCache.delete(evalCache.keys().next().value);
  }
  return copyResult(res);
}

function copyResult(res) {
  return res.advisory ? { ...res, advisory: { ...res.advisory } } : { ...res };
}

module.exports = {
  evaluate,
  ADVISORY_BY_DEFAULT,
  analyzePrompt: evaluate,
  loadCustomConfig,
  redactSecrets,
  redactScanSecrets,
  redactScanRules,
  sanitizeToolResult,
  normalizeInput,
  invisibleView,
  scanWindows,
  MAX_SCAN_CHARS,
  MAX_TOOL_RESULT_SCAN_CHARS,
  MAX_FILTERED_VALUE,
  MAX_FILTERED_CHARS,
  SCAN_WINDOW_OVERLAP,
  SCAN_HEAD_CHARS,
  SCAN_TAIL_CHARS,
  EVAL_CACHE_MAX_INPUT,
  // Helper patterns used by normalization and the hidden-element check,
  // exported so the Python port can be checked against them.
  HELPER_PATTERNS: { ZERO_WIDTH_RE, ANSI_ESCAPE_RE, B64_EXEC_RE, WHITESPACE_RUN_RE, OPEN_TAG_RE, HIDDEN_ATTR_RE, HIDDEN_PAYLOAD_RE, MD_IMAGE_RE, MD_URL_SCHEME_RE, MD_URL_SECRET_PARAM_RE,
    RU_FORGET_RE, RU_FORGET_OBJECT_RE, RU_IGNORE_RE, RU_IGNORE_OBJECT_RE, RU_PHRASE_RE,
    ZH_IGNORE_RE, ZH_IGNORE_OBJECT_RE, ZH_FORGET_RE, ZH_FORGET_OBJECT_RE, ZH_PHRASE_RE,
    CREDENTIAL_URL_RE, CREDENTIAL_STORE_RE, CREDENTIAL_CODE_ROOT_RE, CREDENTIAL_PLACEHOLDER_RE, CREDENTIAL_REFERENCE_RE, CREDENTIAL_REFERENCE_NAME_RE, CREDENTIAL_PLACEHOLDER_MARK_RE,
    CREDENTIAL_PLACEHOLDER_WORDS, CREDENTIAL_CODE_RE, CREDENTIAL_IDENTIFIER_RE, CREDENTIAL_PATH_RE,
    CREDENTIAL_FILE_NAME_RE, CREDENTIAL_HOST_NAME_RE, CREDENTIAL_SLUG_RE, CREDENTIAL_SLUG_SHORT_WORD_RE, CREDENTIAL_OBJECT_NAME_RE,
    CREDENTIAL_DOTTED_WORDS_RE, CREDENTIAL_FILE_EXT_RE, CREDENTIAL_LETTERS_RE, CREDENTIAL_DESCRIPTIVE_WORDS, CREDENTIAL_HEX_RE, WORD_TOKEN_RE,
  },
  SECRET_PATTERNS,
  SCAN_SECRET_PATTERNS,
  RULES_VERSION,
  INJECTION_RULES,
  INDIRECT_INJECTION_RULES,
  EVASION_RULES,
  EXFIL_RULES,
  SENSITIVE_PATH_RULES,
  MARKDOWN_EXFIL_RULES,
};
