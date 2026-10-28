'use strict';

/*
 * A cheap test run before the local rules check a window of tool output (see
 * outputInstructionNote in runner.js). It answers "can any blocking rule match
 * this text?" and may only err toward yes: when it says no, the full rules would
 * have allowed the text too, so the verdict never changes, it is only reached
 * sooner. Starting the rules cold costs several milliseconds, which is most of
 * what the check adds to a hook run on a large, ordinary output.
 *
 * It only decides for plain ASCII text. Anything with a non-ASCII character
 * (invisible characters, homoglyphs, bidirectional marks, other scripts), an
 * ANSI escape or a C-style comment goes to the full rules, because the rules
 * normalise those before matching. In plain ASCII text the only normalisation
 * left is joining words split across lines, which removes whitespace; so the
 * hints below are looked for in the text with all whitespace removed, and every
 * hint is written without whitespace.
 *
 * Each hint is a literal that a blocking rule of lib/rules.js cannot match
 * without. test/hooks_output_prefilter.test.js fails when a blocking rule has no
 * sample there, and runs every shared rule sample through this test, so this list is reviewed
 * together with the rules.
 */

const NON_ASCII_RE = /[^\x00-\x7f]/;
const NORMALIZED_AWAY_RE = /\x1b|\/\*/;
const WHITESPACE_RE = /\s+/g;
const MAX_PREFILTER_CHARS = 256 * 1024;

// Injection, markup, path and encoding rules: one literal each is enough ("ignor" covers the
// Spanish, Portuguese, French and German forms of "ignore"; the other phrases of those languages have their own).
const HINT_RE = /ignor|disregard|forget|youarenow|newinstruction|system|actas|pretend|roleplay|jailbreak|bypass|override|olvida|actuacomo|ahoraeres|oublie|agiscomme|tuesmaintenant|vergiss|dubistjetzt|handleals|\[\/?inst\]|<<<sys|<\/<<sys|<\|im_(?:start|end)\|>|\.ssh|\.aws|\/etc\/(?:shadow|passwd)|\.env|!\[|base64|openssl/i;

// Credential requests: a request verb and a credential word.
const EXFIL_VERB_RE = /give|reveal|send|show|print|expose|leak|paste|dump|read|open|cat|fetch|extract|steal/i;
const EXFIL_OBJECT_RE = /password|secret|credential|token|api[_-]?key|ssh[_-]?key|private[_-]?key|aws_secret|aws_access/i;

// Identity requests (pi:identity_request, pi:identity_request_multi): every match names a person
// (user, operator, owner, an e-mail address, "who") and a place to put it (header, cookie, URL
// parameter, form field, body, next request), in English or in the ASCII spellings of the Spanish,
// Portuguese, French and German forms; the "who is your user" phrasings and the commands whoami and
// git config user.* have their own literals. Non-ASCII spellings (accents, Cyrillic, Chinese) never
// reach these tests, they go to the full rules. The groups are copied from the alternations of the
// two patterns in lib/rules.js, written without whitespace and widened to stems where that is cheaper.
const IDENTITY_PERSON_RE = /user|operator|owner|human|principal|customer|accountholder|who|e-?mail|usuario|operador|dueno|propietario|dono|proprietario|utilisateur|nutzer|benutzer|bediener|betreiber|besitzer/i;
const IDENTITY_PLACE_RE = /header|x-|urlparam|query|\?[a-z_]{1,20}=|cookie|formfield|forminput|formdata|body|payload|next(?:request|call|message)|(?:subsequent|following|every|each|outgoing)(?:http)?(?:request|call|fetch)|cabecera|encabezado|cabecalho|en-t|kopfzeile|param|formula|campo|champ|feld|peticion|solicitud|requisicao|requete|url/i;
const IDENTITY_PHRASE_RE = /your(?:user|operator|owner|human|principal)|who(?:your|the)(?:user|operator|owner|human|principal)is|whoyou(?:are|'re)|whoami|gitconfig/i;

// Hidden markup: an opening "<" and a payload word.
const MARKUP_PAYLOAD_RE = /ignore|system|instruction|prompt|bypass|override|exfil|leak|command/i;

/* True when the rules must run on `text`; false only when no blocking rule can match it. */
function mayMatchRules(text, customConfig) {
  if (typeof text !== 'string') return true;
  if (text.length > MAX_PREFILTER_CHARS || NON_ASCII_RE.test(text) || NORMALIZED_AWAY_RE.test(text)) return true;
  // A repository's own rules (.znrules, zn.config.json) are not covered by the hints.
  if (customConfig && (customConfig.bannedPatterns.length > 0 || customConfig.forbiddenPaths.length > 0 || (customConfig.errors && customConfig.errors.length > 0))) return true;
  const squeezed = text.replace(WHITESPACE_RE, '');
  if (HINT_RE.test(squeezed)) return true;
  if (EXFIL_VERB_RE.test(squeezed) && EXFIL_OBJECT_RE.test(squeezed)) return true;
  if (IDENTITY_PERSON_RE.test(squeezed) && IDENTITY_PLACE_RE.test(squeezed)) return true;
  if (IDENTITY_PHRASE_RE.test(squeezed)) return true;
  return squeezed.includes('<') && MARKUP_PAYLOAD_RE.test(squeezed);
}

module.exports = { mayMatchRules };
