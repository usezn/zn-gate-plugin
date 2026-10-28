'use strict';

const fs = require('fs');
const linearRegex = require('./linear-regex');
const { ZERO_WIDTH_RE, INVISIBLE_ASTRAL_RE, spaceInvisible, spaceInvisibleForMatch } = require('./invisible');
const path = require('path');

/**
 * zn deterministic rules engine - SINGLE SOURCE OF TRUTH.
 * RULES_VERSION: 2026-10-25.25
 */

const RULES_VERSION = '2026-10-25.25';

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
  { id: 'pi:identity_request', pattern: new RegExp(String.raw`(?<![A-Za-z0-9_])(?<!never\s)(?<!not\s)(?<!n't\s)(?<!n\u2019t\s)(?<!avoid\s)(?:include|add|put|attach|append|insert|embed|set|send|pass|forward|submit|post|write|specify|provide|supply|encode|inject|place|share|transmit|reveal|disclose|expose)(?![A-Za-z0-9_])[^\n]{0,60}?(?:(?:(?:(?:your|the)\s{1,4}(?:end\s{1,4})?(?:user|operator|owner|human|principal)|your\s{1,4}(?:end\s{1,4})?(?:customer|account\s{1,4}holder))[\x27’]s\s{1,4}(?:(?:full|real|first|last|login|primary|account|email|e-mail)\s{1,4}){0,2}(?:names?|e-?mail(?:\s{1,4}address(?:es)?)?|usernames?|user\s{0,2}ids?|accounts?|api[\s-]{0,2}keys?|access\s{1,4}tokens?|tokens?|credentials?|passwords?|logins?|identity|identifier|phone(?:\s{1,4}number)?|address|keys?|secrets?)|(?:(?:full|real|first|last|login|primary|account|email|e-mail)\s{1,4}){0,2}(?:names?|e-?mail(?:\s{1,4}address(?:es)?)?|usernames?|user\s{0,2}ids?|accounts?|api[\s-]{0,2}keys?|access\s{1,4}tokens?|tokens?|credentials?|passwords?|logins?|identity|identifier|phone(?:\s{1,4}number)?|address|keys?|secrets?)\s{1,4}(?:of|for)\s{1,4}(?:(?:your|the)\s{1,4}(?:end\s{1,4})?(?:user|operator|owner|human|principal)|your\s{1,4}(?:end\s{1,4})?(?:customer|account\s{1,4}holder)))(?![A-Za-z0-9_])[^\n]{0,80}?(?:(?:http\s{1,4}|request\s{1,4}|custom\s{1,4}|response\s{1,4})?headers?|x-[a-z0-9-]{1,40}|url\s{1,4}param(?:eter)?s?|query\s{1,4}(?:string|param(?:eter)?s?)|\?[a-z_]{1,20}=|cookies?|form\s{1,4}(?:fields?|inputs?|data)|(?:request\s{1,4})?(?:body|payload)|next\s{1,4}(?:request|call|message)|(?:subsequent|following|every|each|outgoing)\s{1,4}(?:http\s{1,4})?(?:requests?|calls?|fetch(?:es)?))|(?:(?:http\s{1,4}|request\s{1,4}|custom\s{1,4}|response\s{1,4})?headers?|x-[a-z0-9-]{1,40}|url\s{1,4}param(?:eter)?s?|query\s{1,4}(?:string|param(?:eter)?s?)|\?[a-z_]{1,20}=|cookies?|form\s{1,4}(?:fields?|inputs?|data)|(?:request\s{1,4})?(?:body|payload)|next\s{1,4}(?:request|call|message)|(?:subsequent|following|every|each|outgoing)\s{1,4}(?:http\s{1,4})?(?:requests?|calls?|fetch(?:es)?))[^\n]{0,80}?(?:(?:(?:your|the)\s{1,4}(?:end\s{1,4})?(?:user|operator|owner|human|principal)|your\s{1,4}(?:end\s{1,4})?(?:customer|account\s{1,4}holder))[\x27’]s\s{1,4}(?:(?:full|real|first|last|login|primary|account|email|e-mail)\s{1,4}){0,2}(?:names?|e-?mail(?:\s{1,4}address(?:es)?)?|usernames?|user\s{0,2}ids?|accounts?|api[\s-]{0,2}keys?|access\s{1,4}tokens?|tokens?|credentials?|passwords?|logins?|identity|identifier|phone(?:\s{1,4}number)?|address|keys?|secrets?)|(?:(?:full|real|first|last|login|primary|account|email|e-mail)\s{1,4}){0,2}(?:names?|e-?mail(?:\s{1,4}address(?:es)?)?|usernames?|user\s{0,2}ids?|accounts?|api[\s-]{0,2}keys?|access\s{1,4}tokens?|tokens?|credentials?|passwords?|logins?|identity|identifier|phone(?:\s{1,4}number)?|address|keys?|secrets?)\s{1,4}(?:of|for)\s{1,4}(?:(?:your|the)\s{1,4}(?:end\s{1,4})?(?:user|operator|owner|human|principal)|your\s{1,4}(?:end\s{1,4})?(?:customer|account\s{1,4}holder)))(?![A-Za-z0-9_]))|(?<![A-Za-z0-9_])(?:(?:identify|reveal|disclose|state|report|announce)\s{1,4}(?:to\s{1,4}(?:me|us|this\s{1,4}[a-z]{3,10})\s{1,4})?(?:who\s{1,4})?your\s{1,4}(?:user|operator|owner|human|principal)(?:\s{1,4}is)?(?![A-Za-z0-9_])|(?:tell|inform)\s{1,4}(?:me|us)\s{1,4}who\s{1,4}(?:your|the)\s{1,4}(?:user|operator|owner|human|principal)\s{1,4}is(?![A-Za-z0-9_])|(?:tell|state|say|reveal|report)[^\n]{0,20}?who\s{1,4}you\s{1,4}(?:are|[\x27’]re)\s{1,4}(?:working|acting)\s{1,4}for(?![A-Za-z0-9_]))`, 'i'), description: 'Tool result asks the agent to identify its user or put the user identity in a request' },
  { id: 'pi:identity_request_multi', pattern: new RegExp(String.raw`(?<![A-Za-z0-9_])(?:incluye|incluya|incluyas|añade|añada|agrega|agregue|pon|ponga|envía|envia|envíe|adjunta|adjunte|inserta|pasa|indica|comparte|revela)(?![A-Za-z0-9_])[^\n]{0,60}?(?:(?:(?:usuario|operador|due[ñn]o|propietario)[^\n]{0,30}?(?:correo(?:\s{1,4}electr[oó]nico)?|e-?mail|nombre(?:\s{1,4}completo)?|cuenta|clave(?:\s{1,4}de\s{1,4}api)?|token|credenciales|contrase[ñn]a|identidad)|(?:correo(?:\s{1,4}electr[oó]nico)?|e-?mail|nombre(?:\s{1,4}completo)?|cuenta|clave(?:\s{1,4}de\s{1,4}api)?|token|credenciales|contrase[ñn]a|identidad)[^\n]{0,30}?(?:usuario|operador|due[ñn]o|propietario))[^\n]{0,80}?(?:cabecera|encabezado|header|par[aá]metro|cookie|formulario|campo|(?:siguiente|pr[oó]xima)\s{1,4}(?:petici[oó]n|solicitud)|url)|(?:cabecera|encabezado|header|par[aá]metro|cookie|formulario|campo|(?:siguiente|pr[oó]xima)\s{1,4}(?:petici[oó]n|solicitud)|url)[^\n]{0,80}?(?:(?:usuario|operador|due[ñn]o|propietario)[^\n]{0,30}?(?:correo(?:\s{1,4}electr[oó]nico)?|e-?mail|nombre(?:\s{1,4}completo)?|cuenta|clave(?:\s{1,4}de\s{1,4}api)?|token|credenciales|contrase[ñn]a|identidad)|(?:correo(?:\s{1,4}electr[oó]nico)?|e-?mail|nombre(?:\s{1,4}completo)?|cuenta|clave(?:\s{1,4}de\s{1,4}api)?|token|credenciales|contrase[ñn]a|identidad)[^\n]{0,30}?(?:usuario|operador|due[ñn]o|propietario)))|(?:cabecera|encabezado|header|par[aá]metro|cookie|formulario|campo|(?:siguiente|pr[oó]xima)\s{1,4}(?:petici[oó]n|solicitud)|url)[^\n]{0,60}?(?<![A-Za-z0-9_])(?:incluye|incluya|incluyas|añade|añada|agrega|agregue|pon|ponga|envía|envia|envíe|adjunta|adjunte|inserta|pasa|indica|comparte|revela)(?![A-Za-z0-9_])[^\n]{0,60}?(?:(?:usuario|operador|due[ñn]o|propietario)[^\n]{0,30}?(?:correo(?:\s{1,4}electr[oó]nico)?|e-?mail|nombre(?:\s{1,4}completo)?|cuenta|clave(?:\s{1,4}de\s{1,4}api)?|token|credenciales|contrase[ñn]a|identidad)|(?:correo(?:\s{1,4}electr[oó]nico)?|e-?mail|nombre(?:\s{1,4}completo)?|cuenta|clave(?:\s{1,4}de\s{1,4}api)?|token|credenciales|contrase[ñn]a|identidad)[^\n]{0,30}?(?:usuario|operador|due[ñn]o|propietario))|(?<![A-Za-z0-9_])(?:inclua|inclui|adicione|adiciona|coloque|coloca|envie|envia|anexe|insira|passe|compartilhe|revele)(?![A-Za-z0-9_])[^\n]{0,60}?(?:(?:(?:usu[aá]rio|operador|dono|propriet[aá]rio)[^\n]{0,30}?(?:e-?mail|nome(?:\s{1,4}completo)?|conta|chave(?:\s{1,4}de\s{1,4}api)?|token|credenciais|senha|identidade)|(?:e-?mail|nome(?:\s{1,4}completo)?|conta|chave(?:\s{1,4}de\s{1,4}api)?|token|credenciais|senha|identidade)[^\n]{0,30}?(?:usu[aá]rio|operador|dono|propriet[aá]rio))[^\n]{0,80}?(?:cabe[cç]alho|header|par[aâ]metro|cookie|formul[aá]rio|campo|pr[oó]xima\s{1,4}requisi[cç][aã]o|url)|(?:cabe[cç]alho|header|par[aâ]metro|cookie|formul[aá]rio|campo|pr[oó]xima\s{1,4}requisi[cç][aã]o|url)[^\n]{0,80}?(?:(?:usu[aá]rio|operador|dono|propriet[aá]rio)[^\n]{0,30}?(?:e-?mail|nome(?:\s{1,4}completo)?|conta|chave(?:\s{1,4}de\s{1,4}api)?|token|credenciais|senha|identidade)|(?:e-?mail|nome(?:\s{1,4}completo)?|conta|chave(?:\s{1,4}de\s{1,4}api)?|token|credenciais|senha|identidade)[^\n]{0,30}?(?:usu[aá]rio|operador|dono|propriet[aá]rio)))|(?:cabe[cç]alho|header|par[aâ]metro|cookie|formul[aá]rio|campo|pr[oó]xima\s{1,4}requisi[cç][aã]o|url)[^\n]{0,60}?(?<![A-Za-z0-9_])(?:inclua|inclui|adicione|adiciona|coloque|coloca|envie|envia|anexe|insira|passe|compartilhe|revele)(?![A-Za-z0-9_])[^\n]{0,60}?(?:(?:usu[aá]rio|operador|dono|propriet[aá]rio)[^\n]{0,30}?(?:e-?mail|nome(?:\s{1,4}completo)?|conta|chave(?:\s{1,4}de\s{1,4}api)?|token|credenciais|senha|identidade)|(?:e-?mail|nome(?:\s{1,4}completo)?|conta|chave(?:\s{1,4}de\s{1,4}api)?|token|credenciais|senha|identidade)[^\n]{0,30}?(?:usu[aá]rio|operador|dono|propriet[aá]rio))|(?<![A-Za-z0-9_])(?:inclus|incluez|ajoute|ajoutez|mets|mettez|envoie|envoyez|joins|joignez|insère|insérez|transmets|transmettez|partage|partagez|révèle|révélez)(?![A-Za-z0-9_])[^\n]{0,60}?(?:(?:(?:utilisateur|opérateur|propriétaire)[^\n]{0,30}?(?:e-?mail|courriel|adresse\s{1,4}e-?mail|nom(?:\s{1,4}complet)?|compte|clé(?:\s{1,4}d\x27api)?|jeton|identifiants?|mot\s{1,4}de\s{1,4}passe|identité)|(?:e-?mail|courriel|adresse\s{1,4}e-?mail|nom(?:\s{1,4}complet)?|compte|clé(?:\s{1,4}d\x27api)?|jeton|identifiants?|mot\s{1,4}de\s{1,4}passe|identité)[^\n]{0,30}?(?:utilisateur|opérateur|propriétaire))[^\n]{0,80}?(?:en-t[eê]te|header|param[eè]tre|cookie|formulaire|champ|prochaine\s{1,4}requ[eê]te|url)|(?:en-t[eê]te|header|param[eè]tre|cookie|formulaire|champ|prochaine\s{1,4}requ[eê]te|url)[^\n]{0,80}?(?:(?:utilisateur|opérateur|propriétaire)[^\n]{0,30}?(?:e-?mail|courriel|adresse\s{1,4}e-?mail|nom(?:\s{1,4}complet)?|compte|clé(?:\s{1,4}d\x27api)?|jeton|identifiants?|mot\s{1,4}de\s{1,4}passe|identité)|(?:e-?mail|courriel|adresse\s{1,4}e-?mail|nom(?:\s{1,4}complet)?|compte|clé(?:\s{1,4}d\x27api)?|jeton|identifiants?|mot\s{1,4}de\s{1,4}passe|identité)[^\n]{0,30}?(?:utilisateur|opérateur|propriétaire)))|(?:en-t[eê]te|header|param[eè]tre|cookie|formulaire|champ|prochaine\s{1,4}requ[eê]te|url)[^\n]{0,60}?(?<![A-Za-z0-9_])(?:inclus|incluez|ajoute|ajoutez|mets|mettez|envoie|envoyez|joins|joignez|insère|insérez|transmets|transmettez|partage|partagez|révèle|révélez)(?![A-Za-z0-9_])[^\n]{0,60}?(?:(?:utilisateur|opérateur|propriétaire)[^\n]{0,30}?(?:e-?mail|courriel|adresse\s{1,4}e-?mail|nom(?:\s{1,4}complet)?|compte|clé(?:\s{1,4}d\x27api)?|jeton|identifiants?|mot\s{1,4}de\s{1,4}passe|identité)|(?:e-?mail|courriel|adresse\s{1,4}e-?mail|nom(?:\s{1,4}complet)?|compte|clé(?:\s{1,4}d\x27api)?|jeton|identifiants?|mot\s{1,4}de\s{1,4}passe|identité)[^\n]{0,30}?(?:utilisateur|opérateur|propriétaire))|(?<![A-Za-z0-9_])(?:füge|fuege|sende|schicke|übergib|uebergib|setze|gib|teile|nenne|hänge|binde)(?![A-Za-z0-9_])[^\n]{0,60}?(?:(?:(?:nutzers|benutzers|bedieners|betreibers|besitzers|operators)[^\n]{0,30}?(?:e-?mail(?:-adresse)?|name|vollständigen\s{1,4}namen|konto|api-?schlüssel|schlüssel|token|zugangsdaten|passwort|identität|benutzernamen?)|(?:e-?mail(?:-adresse)?|name|vollständigen\s{1,4}namen|konto|api-?schlüssel|schlüssel|token|zugangsdaten|passwort|identität|benutzernamen?)[^\n]{0,30}?(?:nutzers|benutzers|bedieners|betreibers|besitzers|operators))[^\n]{0,80}?(?:header|kopfzeile|parameter|cookie|formular|feld|nächste\s{1,4}anfrage|url)|(?:header|kopfzeile|parameter|cookie|formular|feld|nächste\s{1,4}anfrage|url)[^\n]{0,80}?(?:(?:nutzers|benutzers|bedieners|betreibers|besitzers|operators)[^\n]{0,30}?(?:e-?mail(?:-adresse)?|name|vollständigen\s{1,4}namen|konto|api-?schlüssel|schlüssel|token|zugangsdaten|passwort|identität|benutzernamen?)|(?:e-?mail(?:-adresse)?|name|vollständigen\s{1,4}namen|konto|api-?schlüssel|schlüssel|token|zugangsdaten|passwort|identität|benutzernamen?)[^\n]{0,30}?(?:nutzers|benutzers|bedieners|betreibers|besitzers|operators)))|(?:header|kopfzeile|parameter|cookie|formular|feld|nächste\s{1,4}anfrage|url)[^\n]{0,60}?(?<![A-Za-z0-9_])(?:füge|fuege|sende|schicke|übergib|uebergib|setze|gib|teile|nenne|hänge|binde)(?![A-Za-z0-9_])[^\n]{0,60}?(?:(?:nutzers|benutzers|bedieners|betreibers|besitzers|operators)[^\n]{0,30}?(?:e-?mail(?:-adresse)?|name|vollständigen\s{1,4}namen|konto|api-?schlüssel|schlüssel|token|zugangsdaten|passwort|identität|benutzernamen?)|(?:e-?mail(?:-adresse)?|name|vollständigen\s{1,4}namen|konto|api-?schlüssel|schlüssel|token|zugangsdaten|passwort|identität|benutzernamen?)[^\n]{0,30}?(?:nutzers|benutzers|bedieners|betreibers|besitzers|operators))|(?:добавь|добавьте|включи|включите|отправь|отправьте|передай|передайте|укажи|укажите|вставь|вставьте)[^\n]{0,60}?(?:(?:(?:пользовател[а-яё]+|оператор[а-яё]*|владельц[а-яё]+|хозяин[а-яё]*)[^\n]{0,30}?(?:почт[а-яё]+|email|e-mail|имя|имени|логин[а-яё]*|аккаунт[а-яё]*|ключ[а-яё]*|токен[а-яё]*|парол[а-яё]+|учётн[а-яё]+\s{1,4}запис[а-яё]+)|(?:почт[а-яё]+|email|e-mail|имя|имени|логин[а-яё]*|аккаунт[а-яё]*|ключ[а-яё]*|токен[а-яё]*|парол[а-яё]+|учётн[а-яё]+\s{1,4}запис[а-яё]+)[^\n]{0,30}?(?:пользовател[а-яё]+|оператор[а-яё]*|владельц[а-яё]+|хозяин[а-яё]*))[^\n]{0,80}?(?:заголов[а-яё]+|header|параметр[а-яё]*|cookie|куки|форм[а-яё]+|поле|следующ[а-яё]+\s{1,4}запрос[а-яё]*|url)|(?:заголов[а-яё]+|header|параметр[а-яё]*|cookie|куки|форм[а-яё]+|поле|следующ[а-яё]+\s{1,4}запрос[а-яё]*|url)[^\n]{0,80}?(?:(?:пользовател[а-яё]+|оператор[а-яё]*|владельц[а-яё]+|хозяин[а-яё]*)[^\n]{0,30}?(?:почт[а-яё]+|email|e-mail|имя|имени|логин[а-яё]*|аккаунт[а-яё]*|ключ[а-яё]*|токен[а-яё]*|парол[а-яё]+|учётн[а-яё]+\s{1,4}запис[а-яё]+)|(?:почт[а-яё]+|email|e-mail|имя|имени|логин[а-яё]*|аккаунт[а-яё]*|ключ[а-яё]*|токен[а-яё]*|парол[а-яё]+|учётн[а-яё]+\s{1,4}запис[а-яё]+)[^\n]{0,30}?(?:пользовател[а-яё]+|оператор[а-яё]*|владельц[а-яё]+|хозяин[а-яё]*)))|(?:заголов[а-яё]+|header|параметр[а-яё]*|cookie|куки|форм[а-яё]+|поле|следующ[а-яё]+\s{1,4}запрос[а-яё]*|url)[^\n]{0,60}?(?:добавь|добавьте|включи|включите|отправь|отправьте|передай|передайте|укажи|укажите|вставь|вставьте)[^\n]{0,60}?(?:(?:пользовател[а-яё]+|оператор[а-яё]*|владельц[а-яё]+|хозяин[а-яё]*)[^\n]{0,30}?(?:почт[а-яё]+|email|e-mail|имя|имени|логин[а-яё]*|аккаунт[а-яё]*|ключ[а-яё]*|токен[а-яё]*|парол[а-яё]+|учётн[а-яё]+\s{1,4}запис[а-яё]+)|(?:почт[а-яё]+|email|e-mail|имя|имени|логин[а-яё]*|аккаунт[а-яё]*|ключ[а-яё]*|токен[а-яё]*|парол[а-яё]+|учётн[а-яё]+\s{1,4}запис[а-яё]+)[^\n]{0,30}?(?:пользовател[а-яё]+|оператор[а-яё]*|владельц[а-яё]+|хозяин[а-яё]*))|(?:添加|加入|包含|附上|发送|传递|提供|填写|放入|带上|附加)[^\n]{0,60}?(?:(?:(?:用户|使用者|操作者|主人|所有者)[^\n]{0,30}?(?:邮箱|电子邮件|电子邮箱|姓名|名字|用户名|账号|帐号|账户|密钥|令牌|凭据|凭证|身份|密码)|(?:邮箱|电子邮件|电子邮箱|姓名|名字|用户名|账号|帐号|账户|密钥|令牌|凭据|凭证|身份|密码)[^\n]{0,30}?(?:用户|使用者|操作者|主人|所有者))[^\n]{0,80}?(?:请求头|头部|标头|header|参数|cookie|表单|字段|下一个请求|下一次请求|下个请求|url|查询字符串)|(?:请求头|头部|标头|header|参数|cookie|表单|字段|下一个请求|下一次请求|下个请求|url|查询字符串)[^\n]{0,80}?(?:(?:用户|使用者|操作者|主人|所有者)[^\n]{0,30}?(?:邮箱|电子邮件|电子邮箱|姓名|名字|用户名|账号|帐号|账户|密钥|令牌|凭据|凭证|身份|密码)|(?:邮箱|电子邮件|电子邮箱|姓名|名字|用户名|账号|帐号|账户|密钥|令牌|凭据|凭证|身份|密码)[^\n]{0,30}?(?:用户|使用者|操作者|主人|所有者)))|(?:请求头|头部|标头|header|参数|cookie|表单|字段|下一个请求|下一次请求|下个请求|url|查询字符串)[^\n]{0,60}?(?:添加|加入|包含|附上|发送|传递|提供|填写|放入|带上|附加)[^\n]{0,60}?(?:(?:用户|使用者|操作者|主人|所有者)[^\n]{0,30}?(?:邮箱|电子邮件|电子邮箱|姓名|名字|用户名|账号|帐号|账户|密钥|令牌|凭据|凭证|身份|密码)|(?:邮箱|电子邮件|电子邮箱|姓名|名字|用户名|账号|帐号|账户|密钥|令牌|凭据|凭证|身份|密码)[^\n]{0,30}?(?:用户|使用者|操作者|主人|所有者))`, 'iu'), description: 'Tool result asks the agent to identify its user or put the user identity in a request (non-English)' },
];

// Cheap necessary conditions for the identity-request rules, checked in front
// of the two (much more expensive) patterns. Every match of
// pi:identity_request has a word for the user (user, operator, owner...) or
// "who", and a place word (header, cookie, URL parameter, form field, next
// request...) or one of its "who is your user" phrasings; every match of
// pi:identity_request_multi has a word for the user and a place word of its
// language. The groups below are copied from the patterns (a test checks
// that), so a text the pattern would match is never skipped.
const IDENTITY_REQUEST_PREFILTERS = [
  new RegExp(String.raw`(?:user|operator|owner|human|principal)|customer|account\s{1,4}holder|who`, 'i'),
  new RegExp(String.raw`(?:(?:http\s{1,4}|request\s{1,4}|custom\s{1,4}|response\s{1,4})?headers?|x-[a-z0-9-]{1,40}|url\s{1,4}param(?:eter)?s?|query\s{1,4}(?:string|param(?:eter)?s?)|\?[a-z_]{1,20}=|cookies?|form\s{1,4}(?:fields?|inputs?|data)|(?:request\s{1,4})?(?:body|payload)|next\s{1,4}(?:request|call|message)|(?:subsequent|following|every|each|outgoing)\s{1,4}(?:http\s{1,4})?(?:requests?|calls?|fetch(?:es)?))|who|your\s{1,4}(?:user|operator|owner|human|principal)`, 'i'),
];
const IDENTITY_REQUEST_MULTI_PREFILTERS = [
  new RegExp(String.raw`(?:usuario|operador|due[ñn]o|propietario)|(?:usu[aá]rio|operador|dono|propriet[aá]rio)|(?:utilisateur|opérateur|propriétaire)|(?:nutzers|benutzers|bedieners|betreibers|besitzers|operators)|(?:пользовател[а-яё]+|оператор[а-яё]*|владельц[а-яё]+|хозяин[а-яё]*)|(?:用户|使用者|操作者|主人|所有者)`, 'iu'),
  new RegExp(String.raw`(?:cabecera|encabezado|header|par[aá]metro|cookie|formulario|campo|(?:siguiente|pr[oó]xima)\s{1,4}(?:petici[oó]n|solicitud)|url)|(?:cabe[cç]alho|header|par[aâ]metro|cookie|formul[aá]rio|campo|pr[oó]xima\s{1,4}requisi[cç][aã]o|url)|(?:en-t[eê]te|header|param[eè]tre|cookie|formulaire|champ|prochaine\s{1,4}requ[eê]te|url)|(?:header|kopfzeile|parameter|cookie|formular|feld|nächste\s{1,4}anfrage|url)|(?:заголов[а-яё]+|header|параметр[а-яё]*|cookie|куки|форм[а-яё]+|поле|следующ[а-яё]+\s{1,4}запрос[а-яё]*|url)|(?:请求头|头部|标头|header|参数|cookie|表单|字段|下一个请求|下一次请求|下个请求|url|查询字符串)`, 'iu'),
];
for (const rule of INJECTION_RULES) {
  const prefilters = rule.id === 'pi:identity_request' ? IDENTITY_REQUEST_PREFILTERS
    : rule.id === 'pi:identity_request_multi' ? IDENTITY_REQUEST_MULTI_PREFILTERS : null;
  if (!prefilters) continue;
  const pattern = rule.pattern;
  rule.prefilters = prefilters;
  rule.test = (text) => prefilters.every((re) => re.test(text)) && pattern.test(text);
}

// Hidden-element detection in two linear passes: find the first opening tag
// whose attributes hide it, then search once for a payload keyword after it.
// OPEN_TAG_RE always matches from a "<name" and consumes the attribute run up
// to the next "<" or ">", so every character is read once; the candidate is
// a tag only when that run is closed by ">". (A single regex with a lazy
// `[\s\S]*?` tail, or an attribute run that may cross "<", re-scans the rest
// of the input from every candidate and is super-linear on crafted markup.)
const OPEN_TAG_RE = /<[a-z0-9]+(?![A-Za-z0-9_])([^<>]*)(>?)/gi;
// What a style attribute must say to hide an element. Spaces are the ASCII ones (the CSS and HTML
// separators), so Node and Python read the same text the same way.
const HIDDEN_ATTR_RE = /(?<![A-Za-z0-9_-])(?:display[\t\n\f\r ]*:[\t\n\f\r ]*none|visibility[\t\n\f\r ]*:[\t\n\f\r ]*hidden|opacity[\t\n\f\r ]*:[\t\n\f\r ]*0(?:\.0+)?(?![0-9.])|font-size[\t\n\f\r ]*:[\t\n\f\r ]*0(?:px)?(?![0-9.])|color[\t\n\f\r ]*:[\t\n\f\r ]*transparent|text-indent[\t\n\f\r ]*:[\t\n\f\r ]*-[0-9]{3,}px)/i;
// An element of at most 1px, or with a clip that leaves nothing visible, or with no height and
// its overflow cut off, is hidden in the way screen-reader-only text is.
const TINY_WIDTH_CSS_RE = /(?<![A-Za-z0-9_-])(?:max-)?width[\t\n\f\r ]*:[\t\n\f\r ]*(?:0(?:\.0+)?(?:[a-z]+|%)?(?![0-9.])|(?:0(?:\.[0-9]+)?|1(?:\.0+)?)(?:px)?(?![0-9.a-z%]))/i;
const TINY_HEIGHT_CSS_RE = /(?<![A-Za-z0-9_-])(?:max-)?height[\t\n\f\r ]*:[\t\n\f\r ]*(?:0(?:\.0+)?(?:[a-z]+|%)?(?![0-9.])|(?:0(?:\.[0-9]+)?|1(?:\.0+)?)(?:px)?(?![0-9.a-z%]))/i;
const OVERFLOW_HIDDEN_CSS_RE = /(?<![A-Za-z0-9_-])overflow(?:-[xy])?[\t\n\f\r ]*:[\t\n\f\r ]*hidden(?![A-Za-z0-9_-])/i;
const CLIP_CSS_RE = /(?<![A-Za-z0-9_-])(?:clip[\t\n\f\r ]*:[\t\n\f\r ]*rect\([\t\n\f\r ]*(?:0|1px)|clip-path[\t\n\f\r ]*:[\t\n\f\r ]*inset\([\t\n\f\r ]*(?:50|100)%)/i;
// One attribute: name, then an optional value (double-quoted, single-quoted
// or bare). An unterminated quote runs to the end of the run, so every
// character is read once.
const ATTR_RE = /([^\t\n\f\r "'<>\/=]+)(?:[\t\n\f\r ]*=[\t\n\f\r ]*(?:"([^"]*)"?|'([^']*)'?|([^\t\n\f\r "'<>=`]*)))?/g;
// The classes that hide an element in the common frameworks (a token of the class list).
const CLASS_HIDDEN_RE = /(?:^|[\t\n\f\r ])(?:hidden|visually-hidden|sr-only|d-none|invisible|is-hidden)(?=[\t\n\f\r ]|$)/i;

function isAsciiSpace(c) { return c === 32 || (c >= 9 && c <= 13 && c !== 11); }
function asciiTrim(v) {
  let a = 0;
  let b = v.length;
  while (a < b && isAsciiSpace(v.charCodeAt(a))) a++;
  while (b > a && isAsciiSpace(v.charCodeAt(b - 1))) b--;
  return v.slice(a, b);
}

function styleHides(v) {
  return HIDDEN_ATTR_RE.test(v) || CLIP_CSS_RE.test(v) ||
    (TINY_WIDTH_CSS_RE.test(v) && TINY_HEIGHT_CSS_RE.test(v)) ||
    (OVERFLOW_HIDDEN_CSS_RE.test(v) && TINY_HEIGHT_CSS_RE.test(v));
}

// True when the attributes of an opening tag really hide the element: the
// boolean hidden attribute, aria-hidden="true", a style that hides it, or a class
// that hides it (hidden, sr-only and the like). A name that merely contains the word
// (data-hidden) or a hidden word elsewhere in the tag does not count.
function attrsHide(attrs) {
  for (const m of attrs.matchAll(ATTR_RE)) {
    const name = m[1].toLowerCase();
    const value = m[2] ?? m[3] ?? m[4] ?? '';
    if (name === 'hidden') return true;
    if (name === 'aria-hidden' && asciiTrim(value).toLowerCase() === 'true') return true;
    if (name === 'class' && CLASS_HIDDEN_RE.test(value)) return true;
    if (name === 'style' && styleHides(value)) return true;
  }
  return false;
}
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
    if (m[2] === '>' && attrsHide(m[1])) {
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
    if (m[2] === '>' && attrsHide(m[1])) {
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
    pattern: /(?:^|[\s"'`(\[@])(?:~|\/home\/[^\t\n\f\r \/]+|\/root|[A-Za-z]:[\/\\]Users[\/\\][^\t\n\f\r \/\\"']+(?: [^\t\n\f\r \/\\"']+)*|%(?:USERPROFILE|HOMEPATH)%|\$env:(?:USERPROFILE|HOME)(?![A-Za-z0-9_])|\$\{?(?:HOME|USERPROFILE)\}?)?[\/\\]?\.(?:ssh[\/\\](?:id_rsa|id_ed25519|authorized_keys)|aws[\/\\]credentials|env(?:\.[a-z0-9]+)?)(?![A-Za-z0-9_])|=(?:~|\/home\/[^\t\n\f\r \/]+|\/root|[A-Za-z]:[\/\\]Users[\/\\][^\t\n\f\r \/\\"']+(?: [^\t\n\f\r \/\\"']+)*|%(?:USERPROFILE|HOMEPATH)%|\$env:(?:USERPROFILE|HOME)(?![A-Za-z0-9_])|\$\{?(?:HOME|USERPROFILE)\}?)[\/\\]?\.(?:ssh[\/\\](?:id_rsa|id_ed25519|authorized_keys)|aws[\/\\]credentials|env(?:\.[a-z0-9]+)?)(?![A-Za-z0-9_])|\/etc\/(?:shadow|passwd)(?![A-Za-z0-9_])/i,
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
  'pi:identity_request',
  'pi:identity_request_multi',
]);

function strictMode(options, cfg) {
  return (options && options.strict === true) || process.env.ZN_STRICT === '1' || (cfg && cfg.strict === true);
}

// Local custom rules cache (.znrules or zn.config.json)
let customConfig = null;
let lastConfigCheck = 0;

class RulesFileError extends Error {}

// Where a JSON file stops being valid, as "line L, column C" and nothing from the file itself.
function jsonPlace(text, err) {
  const m = /position (\d+)/.exec(err && err.message ? err.message : '');
  if (!m) return 'the file is not valid JSON';
  const pos = Math.min(Number(m[1]), text.length);
  let line = 1;
  let col = 1;
  for (let k = 0; k < pos; k++) {
    if (text.charCodeAt(k) === 10) { line++; col = 1; } else col++;
  }
  return `the file is not valid JSON at line ${line}, column ${col}`;
}

// Reads the project's rules into a new object. Nothing is applied until the whole
// file has been read and every pattern has been checked: a file that cannot be read,
// is not valid JSON, or holds a pattern that is not accepted (see lib/linear-regex.js)
// gives a config with `errors`, and the rules then block until the file is fixed.
function loadCustomConfig(forceReload = false) {
  const now = Date.now();
  if (!forceReload && customConfig !== null && now - lastConfigCheck < 5000) {
    return customConfig;
  }
  lastConfigCheck = now;
  const next = { bannedPatterns: [], forbiddenPaths: [], strict: false, errors: [], file: null };
  const budget = { left: linearRegex.MAX_TOTAL_PROGRAM };
  const addPattern = (src, where) => {
    if (next.bannedPatterns.length >= linearRegex.MAX_PATTERNS) {
      next.errors.push(`${where}: more than ${linearRegex.MAX_PATTERNS} custom patterns`);
      return;
    }
    const res = linearRegex.compileCustomPattern(src, budget);
    if (res.ok) next.bannedPatterns.push(res.rule);
    else next.errors.push(`${where}: ${res.error}`);
  };

  const candidates = [
    path.join(process.cwd(), '.znrules'),
    path.join(process.cwd(), 'zn.config.json'),
  ];

  for (const file of candidates) {
    if (!fs.existsSync(file)) continue;
    next.file = path.basename(file);
    try {
      let text;
      try {
        text = fs.readFileSync(file, 'utf8');
      } catch (err) {
        throw new RulesFileError(`the file cannot be read (${err && err.code ? err.code : 'error'})`);
      }
      if (file.endsWith('.json')) {
        let parsed;
        try {
          parsed = JSON.parse(text);
        } catch (err) {
          throw new RulesFileError(jsonPlace(text, err));
        }
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new RulesFileError('the top level must be an object');
        }
        if (parsed.bannedPatterns !== undefined) {
          if (!Array.isArray(parsed.bannedPatterns)) throw new RulesFileError('bannedPatterns must be a list');
          parsed.bannedPatterns.forEach((p, k) => addPattern(p, `bannedPatterns[${k}]`));
        }
        if (parsed.forbiddenPaths !== undefined) {
          if (!Array.isArray(parsed.forbiddenPaths) || !parsed.forbiddenPaths.every((p) => typeof p === 'string')) {
            throw new RulesFileError('forbiddenPaths must be a list of strings');
          }
          next.forbiddenPaths = parsed.forbiddenPaths;
        }
        if (parsed.strict === true) next.strict = true;
      } else {
        text.split('\n').forEach((raw, k) => {
          const line = raw.trim();
          if (!line || line.startsWith('#')) return;
          // `secret:` lines feed the scrubber's exact-value layer; they are
          // values, not patterns, and must never be compiled as regexes.
          if (line.startsWith('secret:')) return;
          if (line === 'strict') { next.strict = true; return; }
          if (line.startsWith('path:')) next.forbiddenPaths.push(line.slice(5).trim());
          else addPattern(line, `line ${k + 1}`);
        });
      }
    } catch (err) {
      // The reason never repeats the text of the file: it goes to the agent and to the audit log.
      next.errors.push(err instanceof RulesFileError ? err.message : 'the file could not be processed');
    }
    break;
  }
  customConfig = next;
  return customConfig;
}

// The block that holds while the project's rules file has errors.
function invalidRulesResult(cfg) {
  const shown = cfg.errors.slice(0, 3).join('; ') + (cfg.errors.length > 3 ? `; and ${cfg.errors.length - 3} more` : '');
  const at = /^(line \d+|bannedPatterns\[\d+\]):/.exec(cfg.errors[0]);
  const fix = at ? `edit ${cfg.file} at ${at[1]} or delete that ${at[1].startsWith('line') ? 'line' : 'entry'}` : `edit ${cfg.file} or delete the file`;
  return {
    verdict: 'block', confidence: 1.0,
    reason: `The project rules in ${cfg.file} are not valid, so zn-gate blocks until they are fixed (${shown}). To fix it, ${fix}. Custom patterns support literals, classes, groups, alternation and the quantifiers ? * + {n,m} only; see the custom rules section of the README. \`zn-gate check\` lists these errors.`,
    rule: 'custom:invalid_rules', engine: 'oss-local', rules_version: RULES_VERSION,
  };
}

const HOMOGLYPH_MAP = {
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0456': 'i', '\u0455': 's', '\u0443': 'y', '\u0445': 'x',
  '\u0410': 'A', '\u0415': 'E', '\u041e': 'O', '\u0420': 'P', '\u0421': 'C',
  // Dotless i and capital dotted I read as i and I.
  '\u0131': 'i', '\u0130': 'I',
};
// Invisible characters removed before matching: zero-width spaces and joiners,
// word joiner, BOM, soft hyphen, variation selectors, the Mongolian vowel separator, the Hangul
// fillers (U+115F, U+1160, U+3164, U+FFA0) and the left-to-right, right-to-left and Arabic letter
// marks (U+200E, U+200F, U+061C). The marks occur in normal Arabic and Hebrew text, so they are only
// removed for matching and counted by the mostly-invisible check, never blocked on their own. The
// embeddings, overrides and isolates (U+202A-202E, U+2066-2069) are not removed here: the
// evasion:bidi_override rule blocks them wherever they appear. The Unicode tag
// characters (U+E0000-E007F) and the supplementary variation selectors
// (U+E0100-E01EF) are astral. The table is lib/invisible.js (ZERO_WIDTH_RE and INVISIBLE_ASTRAL_RE).
// A line break inside a wrapped token (a key or a base64 blob printed 20 or 40 characters per line):
// at least 10 token characters before and after it, and the next line does not
// start a new NAME= or NAME: assignment. The secret rules also run on the text without these breaks.
// Line breaks are joined only in texts up to this size: wrapped keys are short, and a view of a huge text
// full of short lines would cost far more than it finds (a 32 MB file of 20-character lines).
const MAX_WRAP_VIEW_CHARS = 1 << 20;
const WRAP_BREAK_RE = /(?<=[A-Za-z0-9_\-+/=]{10})[ \t]*\r?\n[ \t]*(?=[A-Za-z0-9_\-+/=]{10})(?![A-Za-z_][A-Za-z0-9_]*[ \t]*[=:](?!=[ \t]*(?:\r?\n|$)))/g;
// WRAP_BREAK_RE tried at one index only. A match holds exactly one line break, and its lookbehind needs a
// token character right before the match, so it can only start where the spaces, tabs and CR before that
// break begin. Trying the pattern there, once per line break, finds the same matches as matchAll, which
// tries it at every index of the text (about 5 ms more per MB of short lines, on every hook call).
const WRAP_BREAK_AT_RE = new RegExp(WRAP_BREAK_RE.source, 'y');
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
  // A character of the ranges without a folded form stays as it is.
  const folded = COMPAT_FOLD.get(run);
  return folded === undefined ? run : folded;
}
const ANSI_ESCAPE_RE = /\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07\x1b]*\x07/g;
// Hard caps for the Base64 smuggling check: above either one the command is blocked.
const MAX_B64_PAYLOADS = 16;
const MAX_B64_DECODED_BYTES = 128 * 1024;
// The payload is group 2 (echo/printf pipe, quoted or not, with options) or group 4 (here-string).
const B64_EXEC_RE = /(?:echo|printf(?:\s+(?:'%s'|"%s"|%s))?)(?:\s+-[A-Za-z]{1,3})*\s+(["']?)([A-Za-z0-9+/=]{16,})\1\s*\|\s*(?:base64\s+-(?:di?|id|-decode)|openssl\s+(?:base64|enc)(?:\s+(?:-[A-Za-z0-9]+|-(?![A-Za-z0-9])))*?\s+-d(?![A-Za-z0-9_]))|base64\s+-(?:di?|id|-decode)\s*<<<\s*(["']?)([A-Za-z0-9+/=]{16,})\3/i;
const B64_EXEC_ALL_RE = new RegExp(B64_EXEC_RE.source, 'gi');

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

// A character of the class WRAP_BREAK_RE reads before and after a line break ([A-Za-z0-9_\-+/=]).
function isWrapChar(c) {
  return (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 95 || c === 45 || c === 43 || c === 47 || c === 61;
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
  if (text.length <= MAX_WRAP_VIEW_CHARS && text.includes('\n')) {
    for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) {
      let start = i;
      if (start > 0 && text[start - 1] === '\r') start--;
      while (start > 0 && (text[start - 1] === ' ' || text[start - 1] === '\t')) start--;
      // WRAP_BREAK_RE starts with a look-behind for ten wrap characters: without one right here it cannot match.
      if (start === 0 || !isWrapChar(text.charCodeAt(start - 1))) continue;
      WRAP_BREAK_AT_RE.lastIndex = start;
      const m = WRAP_BREAK_AT_RE.exec(text);
      if (m) runs.push(start, start + m[0].length);
    }
  }
  if (runs.length === 0) return null;
  // The runs of all patterns are merged in index order (a break run can contain an invisible character).
  const sorted = [];
  for (let r = 0; r < runs.length; r += 2) sorted.push([runs[r], runs[r + 1]]);
  sorted.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const map = new Int32Array(text.length + 1);
  let clean = '';
  let c = 0;
  let pos = 0;
  for (const [start, end] of sorted) {
    if (end <= pos) continue;
    for (let i = pos; i < start; i++) map[c++] = i;
    clean += text.slice(pos, Math.max(pos, start));
    pos = Math.max(pos, end);
  }
  for (let i = pos; i < text.length; i++) map[c++] = i;
  clean += text.slice(pos);
  map[c] = text.length;
  return { clean, map: map.subarray(0, c + 1) };
}

// A value as the secret rules see it: no invisible characters and no wrap breaks.
function cleanValue(str) {
  const s = stripInvisible(str);
  return s.includes('\n') ? s.replace(WRAP_BREAK_RE, '') : s;
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

// evaluate() scans an input longer than MAX_SCAN_CHARS whole, in overlapping
// windows (evaluateOversize() below), and blocks one longer than
// MAX_TOOL_RESULT_SCAN_CHARS (rule size:oversize), so no part of an input is
// left unscanned. Tool results go through scanWindows(), which allows output
// past that limit and only marks it `truncated: true`.
const MAX_SCAN_CHARS = 256 * 1024;

/* Base64 payload smuggling: every `echo|printf ... | base64 -d` in `candidates` is decoded
   and evaluated, not only the first, within hard caps that fail closed.
   Returns {block: a block result or null, advisory}. */
function checkBase64Pipes(candidates, options) {
  let advisory = null;
  const payloads = new Set();
  for (const candidate of candidates) {
    for (const m of candidate.matchAll(B64_EXEC_ALL_RE)) {
      const payload = m[2] || m[4];
      if (payload) payloads.add(payload);
    }
  }
  if (payloads.size > MAX_B64_PAYLOADS) {
    return { block: { verdict: 'block', confidence: 0.99, reason: `Smuggled Base64 execution: more than ${MAX_B64_PAYLOADS} Base64 decode pipes in one command`, rule: 'evasion:base64_smuggling', engine: 'oss-local', rules_version: RULES_VERSION }, advisory };
  }
  let bytes = 0;
  for (const payload of payloads) {
    bytes += Math.floor(payload.length * 3 / 4);
    if (bytes > MAX_B64_DECODED_BYTES) {
      return { block: { verdict: 'block', confidence: 0.99, reason: 'Smuggled Base64 execution: too much Base64 data to inspect', rule: 'evasion:base64_smuggling', engine: 'oss-local', rules_version: RULES_VERSION }, advisory };
    }
    try {
      const decoded = Buffer.from(payload, 'base64').toString('utf8');
      const innerRes = evaluate(decoded, options);
      if (innerRes.advisory && !advisory) advisory = innerRes.advisory;
      if (innerRes.verdict === 'block') {
        return {
          block: { ...innerRes, reason: `Smuggled Base64 execution: ${innerRes.reason || innerRes.rule}`, rule: 'evasion:base64_smuggling' },
          advisory,
        };
      }
    } catch (e) {
      // ignore invalid base64
    }
  }
  return { block: null, advisory };
}

function evaluateOversize(input, options) {
  if (input.length > MAX_TOOL_RESULT_SCAN_CHARS) {
    return {
      verdict: 'block', confidence: 1.0, rule: 'size:oversize', reason: 'Input too large to scan in full',
      engine: 'oss-local', rules_version: RULES_VERSION, truncated: true,
    };
  }
  // A Base64 pipe longer than the window overlap can straddle two windows and be cut in both:
  // the pipes are found in the whole input first. The windows still check normalized text.
  const b64 = checkBase64Pipes([input], options);
  if (b64.block) return b64.block;
  return scanWindows(input, { ...options, maxScanChars: MAX_TOOL_RESULT_SCAN_CHARS });
}

// A run of two or more empty or whitespace-only lines becomes one empty line before any rule runs, so text
// that follows a long padding run is read in the same scan window as the text before it. Whitespace here is
// listed explicitly (not \s) so Node.js and Python agree. Done by scanning, not with one repeated regex group,
// which overflows the regex stack on millions of lines; every line is looked at once.
const BLANK_RUN_TEST = /\n[ \t\r\f\v\u0085\u00a0\u00ad\u1680\u2000-\u200d\u2028\u2029\u202f\u205f\u2060\u3000\ufeff]*\n[ \t\r\f\v\u0085\u00a0\u00ad\u1680\u2000-\u200d\u2028\u2029\u202f\u205f\u2060\u3000\ufeff]*\n/;
const BLANK_SPACE = /[ \t\r\f\v\u0085\u00a0\u00ad\u1680\u2000-\u200d\u2028\u2029\u202f\u205f\u2060\u3000\ufeff]*/y;
function collapseBlankRuns(text) {
  if (typeof text !== 'string' || !BLANK_RUN_TEST.test(text)) return text;
  const out = [];
  let copied = 0;
  let i = text.indexOf('\n');
  while (i !== -1) {
    // `i` is a line break; count the blank lines that follow it, each ended by a line break (up to `j`).
    let j = i;
    let blanks = 0;
    for (;;) {
      const k = text.indexOf('\n', j + 1);
      if (k === -1) break;
      BLANK_SPACE.lastIndex = j + 1;
      BLANK_SPACE.exec(text);
      if (BLANK_SPACE.lastIndex !== k) break;
      blanks++;
      j = k;
    }
    if (blanks >= 2) {
      out.push(text.slice(copied, i), '\n\n');
      copied = j + 1;
    }
    i = text.indexOf('\n', j + 1);
  }
  out.push(text.slice(copied));
  return out.join('');
}

function evaluateUncached(input, options = {}) {
  if (typeof input !== 'string') {
    return { verdict: 'allow', confidence: 1.0, rule: 'none', reason: null, engine: 'oss-local', rules_version: RULES_VERSION };
  }
  // Invisible padding is judged on the input as received: collapsing first would turn lines made only of
  // zero-width characters into one empty line and hide a size:invisible block.
  if (input.length > MAX_SCAN_CHARS && tooInvisible([input])) return invisibleBlock();
  input = collapseBlankRuns(input);
  if (input.length > MAX_SCAN_CHARS) return evaluateOversize(input, options);

  // Pre-normalization passes: stripped (preserves non-Latin) and normalized (maps homoglyphs)
  const { normalized, stripped } = normalizeInput(input);

  const strict = strictMode(options, loadCustomConfig());
  let tierAdvisory = null;

  const b64 = checkBase64Pipes([normalized, stripped], options);
  if (b64.block) return b64.block;
  const b64Advisory = b64.advisory;

  // Check against normalized, stripped, and raw input
  const targetList = [normalized, stripped, input];
  // An invisible character used as a space ("ignore<U+3164>all previous instructions") joins the words in the
  // stripped views, so the same passes also run with each invisible character replaced by a space.
  const spacedInput = spaceInvisibleForMatch(input);
  if (spacedInput !== input) {
    const spaced = normalizeInput(spacedInput);
    targetList.push(spaced.normalized, spaced.stripped, spacedInput);
  }
  const targets = Array.from(new Set(targetList));

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
  if (cfg.errors.length > 0) return invalidRulesResult(cfg);
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
  { id: 'secret:private_key', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----(?:(?!-----BEGIN )[\s\S])*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/g, replacement: '[REDACTED_PRIVATE_KEY]' },
  { id: 'secret:anthropic_key', pattern: /(?<![A-Za-z0-9_])(sk-ant-[A-Za-z0-9_-]{30,})(?:(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]))/g, replacement: '[REDACTED_ANTHROPIC_KEY]' },
  // A key without a known prefix ends at the first character that is not a letter or digit.
  { id: 'secret:openai_key', pattern: /(?<![A-Za-z0-9_])(sk-(?:(?:proj|svcacct|admin|[Nn]one|or-v1|lf)-[A-Za-z0-9_-]{28,}(?:(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]))|helicone-(?:(?:eu|cp|gov|rl)-){0,4}[a-z0-9]{7}(?:-[a-z0-9]{7}){3}(?![a-z0-9])|(?=(?:eu|cp|gov|rl)-|[a-z0-9]{7}-)(?=[a-z-]{0,46}[0-9])(?:(?:eu|cp|gov|rl)-){0,4}[a-z0-9]{7}(?:-[a-z0-9]{7}){3}(?![a-z0-9])(?!-[a-z0-9])|sp-[A-Za-z0-9]{28,}(?![A-Za-z0-9])|[A-Za-z0-9]{28,}(?![A-Za-z0-9])|(?:(?!sk-)[A-Za-z0-9_-]){1,200}?T3BlbkFJ[A-Za-z0-9_-]{20,}(?:(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]))))/g, replacement: '[REDACTED_OPENAI_KEY]' },
  { id: 'secret:aws_access_key', pattern: /(?<![A-Za-z0-9_])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9_])/g, replacement: '[REDACTED_AWS_KEY]' },
  { id: 'secret:aws_secret_key', pattern: /((?:[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy]|[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]|[Aa][Ww][Ss]_[Kk][Ee][Yy])\s*[:=]\s*['"]?)([A-Za-z0-9/+=]{40})(['"]?)/g, replacement: '$1[REDACTED_AWS_SECRET]$3' },
  { id: 'secret:github_token', pattern: /(?<![A-Za-z0-9_])((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{82})(?![A-Za-z0-9_])/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { id: 'secret:db_url_password', pattern: /((?:[Pp][Oo][Ss][Tt][Gg][Rr][Ee][Ss](?:[Qq][Ll])?|[Mm][Yy][Ss][Qq][Ll]|[Mm][Oo][Nn][Gg][Oo][Dd][Bb](?:\+[Ss][Rr][Vv])?|[Rr][Ee][Dd][Ii][Ss]|[Aa][Mm][Qq][Pp])(?:\+[A-Za-z0-9_]+)?:\/\/[^:\s\/]+:)(?!(?:\$\{(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*)\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_][A-Z0-9_]*%|<[A-Za-z][A-Za-z_-]{0,63}>|\{\{\s*[A-Za-z_][A-Za-z_.]*\s*\}\})@)([^@\s\/]+)(@)/g, replacement: '$1[REDACTED_DB_PASSWORD]$3' },
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
// True when a rule of `patterns` matches starting at the first non-space character after `from`
// (before `limit`): the next line starts a secret of its own, so it is not the tail of a wrapped one.
const STICKY = new WeakMap();
function startsSecretAt(text, from, limit, patterns) {
  let pos = from;
  while (pos < limit && /\s/.test(text[pos])) pos++;
  if (pos >= limit) return false;
  for (const p of patterns) {
    let re = STICKY.get(p);
    if (!re) {
      re = new RegExp(p.pattern.source, p.pattern.flags.replace(/[gy]/g, '') + 'y');
      STICKY.set(p, re);
    }
    re.lastIndex = pos;
    if (re.test(text)) return true;
  }
  return false;
}

// The spaced view of the last text a rule was run on (see spaceInvisible), so the many rules of one text
// build it once.
let spacedMemo = { text: null, spaced: null };
function spacedView(text) {
  if (spacedMemo.text !== text) spacedMemo = { text, spaced: spaceInvisible(text) };
  return spacedMemo.spaced;
}

function ruleCandidates(item, text, view, budget, out, patterns = null) {
  const passes = view ? [[text, null], [view.clean, view.map]] : [[text, null]];
  // A third pass reads each invisible character as a space; its indexes are the original ones.
  if (view) {
    const spaced = spacedView(text);
    if (spaced !== text) passes.push([spaced, null, true]);
  }
  // Spans this rule found on the original text. A match on the view that overlaps two or more of them is
  // dropped, so two secrets on consecutive lines are not merged into one match across the break. A view
  // match that extends a single original match (the first line of a wrapped key) is kept, unless the next
  // line starts a secret of its own (startsSecretAt). They come in order and without overlaps, so the
  // ones a view match overlaps are counted with two binary searches.
  const foundStarts = [];
  const foundEnds = [];
  const flags = item.pattern.flags.includes('d') ? item.pattern.flags : item.pattern.flags + 'd';
  const regex = new RegExp(item.pattern.source, flags);
  for (const [hay, map, spaced] of passes) {
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
        const value = cleanValue(text.slice(groups[2][0], groups[2][1]));
        const prefix = groups[1] ? cleanValue(text.slice(groups[1][0], groups[1][1])) : '';
        const n = value.length;
        if (n <= MAX_FILTERED_VALUE && n <= budget.left) {
          budget.left -= n;
          if (item.valueFilter(value, prefix)) continue;
        }
      }
      const [start, end] = spanIn(map, m.index, m.index + m[0].length);
      if (spaced) {
        // Same indexes as the original: the span cannot join two matches, and it is not in order.
      } else if (!map) {
        foundStarts.push(start);
        foundEnds.push(end);
      } else {
        const first = upperBound(foundEnds, start);
        const over = lowerBound(foundStarts, end) - first;
        if (over >= 2) continue;
        if (over === 1 && patterns && startsSecretAt(text, foundEnds[first], end, patterns)) continue;
      }
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

// ---------------------------------------------------------------------------
// Quoted credentials. The assignment rules read one word, so the rest of
// `"api_key":"abcdefghijkl mno pqr"` would stay in the clear. Two kinds of
// value are read here, before the other rules (the Python package does the
// same in _find_quoted_credentials):
//   - a quoted value of a secret key that has whitespace in it, up to its
//     closing quote. A double-quoted value ends at the first quote that is not
//     escaped, a single-quoted one at the next ', and a value inside an escaped
//     JSON string at its own escaped quote;
//   - a bare number of 8 or more characters under a QUOTED key. The
//     replacement is written as a string, so the JSON stays valid. A number
//     under an unquoted key (YAML, shell) is left alone.
// Values shorter than 8 characters, placeholders and values with no closing
// quote inside KV_MAX_VALUE characters are left alone. One pass over the text,
// and each opener reads at most KV_MAX_VALUE characters.
// ---------------------------------------------------------------------------
// Groups: 1 = name, 2 = the quote that closes a quoted key (with the backslashes
// of a JSON string inside a string), 3 = the opening quote of the value (same
// escapes). The name takes no suffix, so password_hint and token_count are other keys.
const KV_OPEN_RE = new RegExp('(password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token)(\\\\{0,2}["\'])?[ \\t]{0,16}(?:=>|:=|=|:)[ \\t]{0,16}(\\\\{0,2}["\'])?', 'gi');
const KV_PREFILTER_RE = /pass|secret|token|api[_-]?key|access[_-]?key|private[_-]?key/i;
const KV_MAX_VALUE = 4096;
const KV_MIN_VALUE = 8;
const KV_NUMBER_RE = /-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const KV_MASK_RE = /^-?([0-9])\1+$/;
const KV_WORD_CHAR_RE = /[A-Za-z0-9_.-]/;
const KV_WORD_RUN_RE = /[A-Za-z0-9_.-]*/y;
const KV_AUTH_WORD_RE = /^(?:bearer|basic|token)\s+/i;
// A placeholder, or a reference after an auth scheme word ("Bearer ${TOKEN}").
const KV_PLACEHOLDER_RE = /^(?:x{3,}|\*{3,}|\.{3,}|-+|_+|<[^>]*>|\$\{?[^}]*\}?|\{\{?[^}]*\}?\}|%\(?[a-z_]*\)?s|:[a-z_]+|\[[^\]]*\])$/i;
const KV_PLACEHOLDER_WORDS_RE = /(?:^|[^a-z])(?:password|passwd|passw0rd|secret|changeme|change_me|example|placeholder|your[_-]?|redacted|dummy|sample|foobar|hunter2|xxxx|todo|insert|replace|mypass|pass(?:word)?123)(?:[^a-z]|$)/i;
const KV_REPEAT_RE = /^([^\n\r\u2028\u2029])\1+$/u;
const QUOTED_CREDENTIAL_RULE = 'secret:quoted_credential';
const KV_REPLACEMENT = '[REDACTED_SECRET]';

function kvBarePlaceholder(value) {
  return KV_PLACEHOLDER_RE.test(value) || KV_PLACEHOLDER_WORDS_RE.test(value) || KV_REPEAT_RE.test(value);
}

function kvPlaceholder(value) {
  if (kvBarePlaceholder(value)) return true;
  const m = KV_AUTH_WORD_RE.exec(value);
  return m !== null && kvBarePlaceholder(value.slice(m[0].length));
}

// Index of the closing quote of a value that starts at `start`, or -1. The
// window is KV_MAX_VALUE characters; a backslash run is counted once (the scan
// jumps past it), so the work stays linear.
function kvClosingQuote(text, start, quote, level) {
  const n = text.length;
  const limit = Math.min(n, start + KV_MAX_VALUE);
  let i = start;
  if (level === 0) {
    const q = quote.charCodeAt(0);
    while (i < limit) {
      const c = text.charCodeAt(i);
      if (c === q) return i;
      // In a double-quoted value a backslash escapes the next character; in a single-quoted one it is just a character.
      i += c === 92 && q === 34 ? 2 : 1;
    }
    return -1;
  }
  while (i < limit) {
    if (text.charCodeAt(i) !== 92) {
      i++;
      continue;
    }
    let k = i;
    while (k < n && text.charCodeAt(k) === 92) k++;
    if (k - i === level && text[k] === quote) return i;
    i = k + 1;
  }
  return -1;
}

// Spans {start, end, quote} of the values described above. `quote` is the quote
// that the replacement of a bare number is wrapped in (empty for a quoted value,
// whose own quotes stay).
function findQuotedCredentials(text) {
  const found = [];
  const n = text.length;
  const re = new RegExp(KV_OPEN_RE.source, KV_OPEN_RE.flags);
  let pos = 0;
  for (;;) {
    re.lastIndex = pos;
    const m = re.exec(text);
    if (m === null) break;
    const after = re.lastIndex;
    pos = after;
    const opener = m[3];
    const keyQuote = m[2];
    if (opener === undefined) {
      KV_NUMBER_RE.lastIndex = after;
      const num = KV_NUMBER_RE.exec(text);
      // Only a quoted key (a JSON member or a dict entry) counts.
      if (!keyQuote || num === null || num[0].length < KV_MIN_VALUE) continue;
      const end = after + num[0].length;
      if (end < n && KV_WORD_CHAR_RE.test(text[end])) continue; // part of a longer word, not a number
      if (KV_MASK_RE.test(num[0])) continue;                    // 00000000: a mask
      found.push({ start: after, end, quote: keyQuote });
      pos = end;
      continue;
    }
    const quote = opener[opener.length - 1];
    const level = opener.length - 1;                          // backslashes before the opening quote
    const start = after;
    const end = kvClosingQuote(text, start, quote, level);
    if (end < 0) continue;
    const value = text.slice(start, end);
    if (value.length < KV_MIN_VALUE || !/\s/.test(value) || kvPlaceholder(value)) continue;
    let spanEnd = end;
    if (level === 0 && !keyQuote) {
      // A shell word glued to more quoted pieces ('a b''c') is one value: take them too.
      let p = end + 1;
      for (let k = 0; k < 8; k++) {
        if (p >= n || (text[p] !== '"' && text[p] !== "'")) break;
        KV_WORD_RUN_RE.lastIndex = p + 1;
        const q = p + 1 + KV_WORD_RUN_RE.exec(text)[0].length;
        if (q === p + 1) break;
        spanEnd = q;
        p = q + 1;
      }
    }
    found.push({ start, end: spanEnd, quote: '' });
    pos = spanEnd;
  }
  return found;
}

// The number of values of the sorted array a below x (lowerBound) or at most x (upperBound).
function lowerBound(a, x) {
  let lo = 0;
  let hi = a.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (a[mid] < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function upperBound(a, x) {
  let lo = 0;
  let hi = a.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (a[mid] <= x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

// Redacts the values found by findQuotedCredentials, on the text and on the text
// without invisible characters (as every other rule).
function redactQuotedCredentials(text) {
  if (typeof text !== 'string' || !text || !KV_PREFILTER_RE.test(text)) return { sanitized: text, detections: [] };
  const view = invisibleView(text);
  const passes = view ? [[text, null], [view.clean, view.map]] : [[text, null]];
  const cands = [];
  // The first pass gives its spans in order and without overlaps, so the spans of
  // that pass a later span overlaps are counted with two binary searches.
  const seenStarts = [];
  const seenEnds = [];
  for (const [hay, map] of passes) {
    for (const f of findQuotedCredentials(hay)) {
      const [start, end] = spanIn(map, f.start, f.end);
      if (!map) {
        seenStarts.push(start);
        seenEnds.push(end);
      } else if (lowerBound(seenStarts, end) - upperBound(seenEnds, start) >= 2) continue;
      cands.push({ start, end, rule: QUOTED_CREDENTIAL_RULE, text: f.quote + KV_REPLACEMENT + f.quote });
    }
  }
  if (cands.length === 0) return { sanitized: text, detections: [] };
  const detections = [];
  let out = '';
  let last = 0;
  for (const e of mergeCandidates(cands)) {
    out += text.slice(last, e.start) + e.text;
    last = e.end;
    detections.push({ rule: e.rule, index: e.start });
  }
  return { sanitized: out + text.slice(last), detections };
}

// The quoted values first (the other rules read one word and would leave the
// rest of a value behind), then SECRET_PATTERNS.
function redactCredentials(text) {
  const quoted = redactQuotedCredentials(text);
  const rest = redactWith(quoted.sanitized, SECRET_PATTERNS);
  if (quoted.detections.length === 0) return rest;
  return { sanitized: rest.sanitized, detections: quoted.detections.concat(rest.detections) };
}

// Redacts secrets. Every rule runs on the original text and on the text without
// invisible characters (see ruleCandidates), and the redacted spans are the union
// of what both find, so a secret split by a zero-width or tag character is
// redacted whole. Texts without invisible characters are handled as before.
function redactSecrets(text) {
  const first = redactCredentials(text);
  if (typeof first.sanitized !== 'string' || !first.sanitized) return first;
  const second = redactProviderFormats(first.sanitized);
  if (second.detections.length === 0) return first;
  return { sanitized: second.sanitized, detections: first.detections.concat(second.detections) };
}

// Scrubber secret types that count as provider formats, with the rule id the
// Python package uses for the same format (its PROVIDER_SECRET_PATTERNS). The
// other scrubber types are only redacted by the scrubber itself.
const SCRUB_PROVIDER_RULES = new Map([
  'GITLAB_TOKEN', 'SLACK_TOKEN', 'SLACK_WEBHOOK', 'DISCORD_WEBHOOK', 'STRIPE_KEY', 'STRIPE_WEBHOOK_SECRET',
  'GOOGLE_API_KEY', 'GOOGLE_OAUTH_SECRET', 'HF_TOKEN', 'NPM_TOKEN', 'PYPI_TOKEN', 'SENDGRID_KEY', 'TWILIO_KEY',
  'MAILGUN_KEY', 'SHOPIFY_TOKEN', 'DIGITALOCEAN_TOKEN', 'LINEAR_KEY', 'TELEGRAM_BOT_TOKEN', 'AZURE_STORAGE_KEY',
  'DATABRICKS_TOKEN', 'VAULT_TOKEN', 'DOPPLER_TOKEN', 'NEWRELIC_KEY', 'GROQ_KEY', 'XAI_KEY', 'DOCKERHUB_PAT',
  'ZN_API_KEY', 'TAVILY_KEY', 'FIRECRAWL_KEY', 'POLAR_TOKEN', 'REPLICATE_TOKEN', 'SUPABASE_PAT', 'AZURE_AD_CLIENT_SECRET',
  'SQUARE_TOKEN', 'DISCORD_BOT_TOKEN',
  'ONEPASSWORD_SA_TOKEN', 'AGE_SECRET_KEY', 'ALIBABA_KEY_ID', 'ARTIFACTORY_KEY', 'CLOUDFLARE_ORIGIN_CA_KEY', 'DYNATRACE_TOKEN', 'EASYPOST_KEY', 'FLYIO_TOKEN', 'GRAFANA_TOKEN', 'TERRAFORM_CLOUD_TOKEN', 'HEROKU_KEY_V2', 'NOTION_TOKEN', 'PERPLEXITY_KEY', 'PLANETSCALE_TOKEN', 'POSTMAN_KEY', 'PREFECT_KEY', 'PULUMI_TOKEN', 'README_KEY', 'RUBYGEMS_KEY', 'BREVO_KEY', 'SENTRY_USER_TOKEN', 'SHIPPO_KEY', 'OPENSHIFT_TOKEN', 'TEAMS_WEBHOOK',
  'BEARER_TOKEN',
].map((t) => [t, 'secret:' + t.toLowerCase()]).concat([
  ['AWS_KEY', 'secret:aws_key_id'],
  ['URL_PASSWORD', 'secret:url_password'],
  ['DB_PASSWORD', 'secret:url_password'],
]));

// The scrubber types a URL password as DB_PASSWORD or URL_PASSWORD by scheme;
// the Python package has one rule and one label for every scheme.
const SCRUB_PROVIDER_LABELS = new Map([['DB_PASSWORD', 'URL_PASSWORD']]);

// The provider token formats of the scrubber engine (GitLab, Slack, Stripe,
// Google, npm, ...), run on text the SECRET_PATTERNS already redacted. The
// engine is required here, not at the top, because it requires this file.
function redactProviderFormats(text) {
  // Only the provider types take part in the overlap resolution: a wider span of another type (such as
  // a NAME=value assignment) would otherwise win it, be dropped here, and leave the key unredacted.
  const spans = require('./scrub/engine').scan(text, { exact: false, pii: false, types: SCRUB_PROVIDER_RULES })
    .sort((a, b) => a.start - b.start || b.end - a.end);
  const detections = [];
  let out = '';
  let last = 0;
  for (const s of spans) {
    if (s.start < last) continue;
    detections.push({ rule: SCRUB_PROVIDER_RULES.get(s.type), index: s.start });
    out += text.slice(last, s.start) + `[REDACTED_${SCRUB_PROVIDER_LABELS.get(s.type) || s.type}]`;
    last = s.end;
  }
  return { sanitized: out + text.slice(last), detections };
}

// SCAN_SECRET_PATTERNS alone (`zn-gate scan` runs them last, on text that
// the other rules and the scrubber already redacted).
function redactScanRules(text) {
  return redactWith(text, SCAN_SECRET_PATTERNS);
}

// redactSecrets plus SCAN_SECRET_PATTERNS, for the lines `zn-gate scan` prints.
function redactScanSecrets(text) {
  const first = redactCredentials(text);
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
    ruleCandidates(item, sanitized, view, budget, cands, patterns);
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
// is added and the result is marked `truncated: true`; options.maxScanChars
// raises that limit (the MCP shield scans more). A match that spans more than
// SCAN_WINDOW_OVERLAP characters across a window boundary can be missed.
const SCAN_WINDOW_OVERLAP = 4 * 1024;
const MAX_TOOL_RESULT_SCAN_CHARS = 4 * 1024 * 1024;

// Tool output that is mostly invisible characters is not scanned: building the
// match view of millions of zero-width characters costs seconds, and a text
// that is mostly invisible has no legitimate use. It is blocked instead, so
// hidden text cannot pass because it was too costly to look at.
// The invisible characters are counted over every string of a result together
// (splitting the text into small strings does not avoid the limit), in code
// points (Python counts the same way). A result is blocked when it has at
// least MIN_INVISIBLE_CHECK_CHARS code points and more than half are invisible,
// or when it holds more than MAX_INVISIBLE_CHARS invisible characters. The
// count stops as soon as that limit is passed. A valid subdivision flag
// (U+1F3F4, 2 to 7 tag letters or digits, U+E007F) counts as one invisible
// character, so long runs of such flags are not read as hidden text.
const MIN_INVISIBLE_CHECK_CHARS = 64 * 1024;
const MAX_INVISIBLE_CHARS = 200000;
const INVISIBLE_BLOCK_REASON = 'Output is mostly invisible characters';

// The characters invisibleStats counts or pairs up: the invisible ones and any high surrogate (the start of a
// pair). A text with none of them has nothing to count, and one native scan says so far faster than the loop.
const INVISIBLE_STATS_CANDIDATE_RE = /[\u00AD\u061C\u115F\u1160\u180E\u200B-\u200F\u2060\u3164\uFEFF\uFE00-\uFE0F\uFFA0\uD800-\uDBFF]/;

function invisibleStats(text, budget) {
  const n = text.length;
  if (!INVISIBLE_STATS_CANDIDATE_RE.test(text)) return { count: 0, length: n };
  let count = 0;
  let pairs = 0;
  for (let i = 0; i < n; i++) {
    const c = text.charCodeAt(i);
    if (c < 0xAD) continue;
    if ((c >= 0x200B && c <= 0x200F) || c === 0x2060 || c === 0xFEFF || c === 0xAD || (c >= 0xFE00 && c <= 0xFE0F) || c === 0x61C || c === 0x180E || c === 0x115F || c === 0x1160 || c === 0x3164 || c === 0xFFA0) {
      count++;
    } else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < n) {
      const d = text.charCodeAt(i + 1);
      if (d < 0xDC00 || d > 0xDFFF) continue;
      pairs++;
      i++;
      if (c === 0xDB40) {
        if (d <= 0xDC7F || (d >= 0xDD00 && d <= 0xDDEF)) count++;
      } else if (c === 0xD83C && d === 0xDFF4) {
        let j = i + 1;
        let k = 0;
        while (k < 7 && text.charCodeAt(j) === 0xDB40) {
          const e = text.charCodeAt(j + 1);
          if (!((e >= 0xDC30 && e <= 0xDC39) || (e >= 0xDC61 && e <= 0xDC7A))) break;
          j += 2;
          k++;
        }
        if (k >= 2 && text.charCodeAt(j) === 0xDB40 && text.charCodeAt(j + 1) === 0xDC7F) {
          count++;
          pairs += k + 1;
          i = j + 1;
        }
      }
    }
    if (count > budget) break;
  }
  return { count, length: n - pairs };
}

function tooInvisible(strings) {
  let count = 0;
  let length = 0;
  for (const s of strings) {
    if (typeof s !== 'string') continue;
    const st = invisibleStats(s, MAX_INVISIBLE_CHARS - count);
    count += st.count;
    length += st.length;
    if (count > MAX_INVISIBLE_CHARS) return true;
  }
  return length >= MIN_INVISIBLE_CHECK_CHARS && count * 2 > length;
}

function invisibleBlock() {
  return { verdict: 'block', confidence: 1.0, reason: INVISIBLE_BLOCK_REASON, rule: 'size:invisible', engine: 'oss-local', rules_version: RULES_VERSION };
}

// A result whose middle was not scanned (over MAX_TOOL_RESULT_SCAN_CHARS) is
// blocked by default. options.allowTruncated or ZN_ALLOW_TRUNCATED=1 opts out;
// options.blockTruncated or ZN_BLOCK_TRUNCATED=1 (the former opt-in) still
// forces the block and wins over the opt-out.
function truncatedBlocks(options) {
  if (options.blockTruncated === true || process.env.ZN_BLOCK_TRUNCATED === '1') return true;
  return !(options.allowTruncated === true || process.env.ZN_ALLOW_TRUNCATED === '1');
}

function scanWindows(text, options = {}) {
  if (tooInvisible([text])) return invisibleBlock();
  text = collapseBlankRuns(text);
  if (typeof text !== 'string' || text.length <= MAX_SCAN_CHARS) return evaluate(text, options);
  const step = MAX_SCAN_CHARS - SCAN_WINDOW_OVERLAP;
  const cap = Number.isFinite(options.maxScanChars) && options.maxScanChars > 0 ? options.maxScanChars : MAX_TOOL_RESULT_SCAN_CHARS;
  const limit = Math.min(text.length, cap);
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
    // Output too large to scan in full is blocked unless the caller opts out
    // with allowTruncated or ZN_ALLOW_TRUNCATED=1 (then it is allowed with
    // `truncated: true`).
    if (truncated && truncatedBlocks(options) && assessment.verdict !== 'block') {
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
      // Keys are text the model reads too, so they are redacted like values. A redacted key that equals another
      // key, clean or redacted, is numbered ("<text> #2") so that no value is lost.
      const entries = Object.entries(val);
      const names = entries.map(([k]) => _sanitize(k));
      const taken = new Set();
      names.forEach((n, i) => { if (n === entries[i][0]) taken.add(n); });
      const out = {};
      for (let i = 0; i < entries.length; i += 1) {
        let name = names[i];
        if (name !== entries[i][0]) {
          const base = name;
          for (let n = 2; taken.has(name); n += 1) name = `${base} #${n}`;
          taken.add(name);
        }
        // defineProperty, so a key such as __proto__ stays an ordinary property
        Object.defineProperty(out, name, { value: _sanitize(entries[i][1]), enumerable: true, writable: true, configurable: true });
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
  QUOTED_CREDENTIAL_RULE,
  redactScanSecrets,
  redactScanRules,
  isNonSecretValue,
  sanitizeToolResult,
  tooInvisible,
  invisibleStats,
  invisibleBlock,
  MAX_INVISIBLE_CHARS,
  MIN_INVISIBLE_CHECK_CHARS,
  normalizeInput,
  invisibleView,
  scanWindows,
  truncatedBlocks,
  MAX_SCAN_CHARS,
  MAX_TOOL_RESULT_SCAN_CHARS,
  MAX_FILTERED_VALUE,
  MAX_FILTERED_CHARS,
  SCAN_WINDOW_OVERLAP,
  EVAL_CACHE_MAX_INPUT,
  // Helper patterns used by normalization and the hidden-element check,
  // exported so the Python port can be checked against them.
  HELPER_PATTERNS: { ZERO_WIDTH_RE, ANSI_ESCAPE_RE, B64_EXEC_RE, WHITESPACE_RUN_RE, OPEN_TAG_RE, HIDDEN_ATTR_RE, TINY_WIDTH_CSS_RE, TINY_HEIGHT_CSS_RE, OVERFLOW_HIDDEN_CSS_RE, CLIP_CSS_RE, ATTR_RE, CLASS_HIDDEN_RE, HIDDEN_PAYLOAD_RE, MD_IMAGE_RE, MD_URL_SCHEME_RE, MD_URL_SECRET_PARAM_RE,
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
