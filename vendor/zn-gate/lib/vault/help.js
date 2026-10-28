'use strict';
/**
 * Help text of the vault commands, printed by `zn <command> --help`.
 * Each entry is the list of lines for one command; the first line is the usage.
 */

const HELP = {
  unlock: [
    'usage: zn unlock [--ttl 8h] [--idle 30m] [--backend NAME] [--passphrase-stdin] [--foreground]',
    'Unlocks the local vault for this session. The first run creates it.',
    '  --ttl DURATION       lock after this long, whatever the use (default 8h; 1m to 24h)',
    '  --idle DURATION      lock after this long without use (default 30m)',
    '  --backend NAME       macos, windows, libsecret or passphrase (default: the one the vault uses)',
    '  --passphrase-stdin   read the passphrase from stdin instead of a hidden prompt',
    '  --foreground         keep the vault in this terminal and approve secret use here',
  ],
  lock: [
    'usage: zn lock',
    'Locks the vault now. Secrets stay unavailable to commands until zn unlock runs again.',
  ],
  vault: [
    'usage: zn vault status | log [--since 1h] | verify | forget [dir] | log export --otlp',
    'Shows and checks the local vault.',
    '  status               whether the vault exists and is unlocked',
    '  log [--since 1h]     who used which secret, and where (no values); also: zn secret log',
    '  verify               check the chain and the MACs of the audit log',
    '  forget [dir]         forget the token map of a project (the vault must be locked)',
    '  log export --otlp    export the audit log as OpenTelemetry logs [--since 7d] [--out FILE]',
  ],
  'env shadow': [
    'usage: zn env shadow [FILE] [--all] [--keys A,B] [--dry-run] [--force] [--mode proxy|env|file] [--host H] [--command C]',
    'Moves the sensitive values of a .env file (default: .env) into the vault and leaves markers in the file.',
    '  --all            move every value, not only the ones whose names look sensitive',
    '  --keys A,B       move only these keys',
    '  --dry-run        list what would move and change nothing',
    '  --force          replace a value already stored under the same name',
    '  --mode           how the secret may be used: proxy, env or file (default proxy, or env with --command)',
    '  --host, --command  allow these hosts or commands to use the value',
    'An encrypted copy of the original file is kept in the vault; zn env unshadow restores it.',
  ],
};

/**
 * The help lines for `zn unlock|lock|vault|env shadow --help`, or null when the
 * arguments are not one of those (the general help or the command's own help answers).
 */
function helpFor(args) {
  if (!args.includes('-h') && !args.includes('--help')) return null;
  const [cmd, sub] = args;
  if (cmd === 'unlock' || cmd === 'lock') return HELP[cmd];
  if (cmd === 'vault') return sub === 'log' ? null : HELP.vault; // `vault log --help` has its own text
  if (cmd === 'env' && sub === 'shadow') return HELP['env shadow'];
  return null;
}

module.exports = { helpFor, HELP };
