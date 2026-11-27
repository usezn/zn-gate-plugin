'use strict';

/*
 * One message for a config file that JSON does not accept (agent settings,
 * MCP configs). It names the likely cause (a byte order mark, comments, or
 * the line of the syntax error), says zn-gate left the file unchanged, and
 * says what to do. Used by lib/agents/config-file.js, claude-code.js and init.js.
 */

const DEFAULT_FIX = 'add the zn-gate hooks by hand (see docs/by-agent.md)';

function isValidJson(text) {
  try {
    JSON.parse(text);
    return true;
  } catch (_) {
    return false;
  }
}

/** True when the text has a // or a slash-star comment outside a double-quoted string. */
function hasComments(text) {
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === '\\') i++; // skip the escaped character
      else if (c === '"') inString = false;
    } else if (c === '"') {
      inString = true;
    } else if (c === '/' && (text[i + 1] === '/' || text[i + 1] === '*')) {
      return true;
    }
  }
  return false;
}

/** The 1-based line of a JSON.parse error, when the message gives a position; null otherwise. */
function errorLine(text, err) {
  const withLine = /\(line (\d+) column \d+\)/.exec(err.message);
  if (withLine) return Number(withLine[1]);
  const withPos = /at position (\d+)/.exec(err.message);
  if (withPos) return text.slice(0, Number(withPos[1])).split('\n').length;
  return null;
}

/**
 * The Error text for a config file that failed to parse. `text` is the file
 * content as read (a leading BOM is allowed), `err` the parser's error, and
 * `fix` the "what to do" phrase after "or". Always ends with "(left unchanged)".
 */
function configParseError(file, text, err, fix = DEFAULT_FIX) {
  const body = text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text;
  const head = 'cannot parse ' + file + ': ';
  if (text.charCodeAt(0) === 0xFEFF && isValidJson(body)) {
    return head + 'the file starts with a byte order mark (BOM), which this reader does not accept. Save it as UTF-8 without BOM (in VS Code, choose "UTF-8" rather than "UTF-8 with BOM"), or ' + fix + '. (left unchanged)';
  }
  if (hasComments(body)) {
    return head + 'the file has comments (JSONC), which JSON does not allow. Remove the comments and any trailing commas, or ' + fix + '. (left unchanged)';
  }
  const line = errorLine(body, err);
  const where = line === null ? '' : ' at line ' + line;
  return head + 'the file is not valid JSON' + where + '. Fix the syntax there (a missing or extra comma, quote or bracket), or ' + fix + '. (left unchanged)';
}

module.exports = { configParseError, hasComments, errorLine, DEFAULT_FIX };
