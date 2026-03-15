#!/usr/bin/env node

// Locksmith CLI
// Usage:
//   locksmith auth                        - Authenticate via Entra device code flow
//   locksmith nonce <service> <scope>     - Request a nonce
//   locksmith rotate <service> <target>   - Trigger rotation
//   locksmith tls status                  - Check all cert status
//   locksmith tls issue <env>             - Issue/renew a cert
//   locksmith tls push-acm <env>          - Push cert to ACM
//   locksmith tls push-servers <env> <id> - Push cert to EC2 instances
//   locksmith tls renew-all               - Renew everything that needs it
//   locksmith ssh cert [principals]       - Get an SSH certificate
//   locksmith status                      - System status

const LOCKSMITH_URL = process.env.LOCKSMITH_URL || 'http://localhost:3100';
const TOKEN = process.env.LOCKSMITH_TOKEN;

const [,, cmd, ...args] = process.argv;

if (!cmd || cmd === 'help') {
  console.log(`
  Locksmith CLI - Zero Trust Credential Lifecycle

  Commands:
    auth                              Authenticate via Entra ID
    nonce <service> <scope>           Request a nonce for a service
    rotate <service> <target>         Trigger credential rotation
    tls status                        Check all TLS cert status
    tls issue <env> [--force]         Issue/renew a TLS cert
    tls push-acm <env> [region]       Push cert to ACM
    tls push-servers <env> <id,...>    Push cert to EC2 instances
    tls renew-all                     Renew all expiring certs
    ssh cert [principal1,principal2]   Get a short-lived SSH certificate
    status                            System status

  Environment:
    LOCKSMITH_URL    Server URL (default: http://localhost:3100)
    LOCKSMITH_TOKEN  Entra ID bearer token (use 'locksmith auth' to get one)

  Auth shortcut:
    eval $(node auth.js --export)     Sets LOCKSMITH_TOKEN automatically
  `);
  process.exit(0);
}

if (cmd === 'auth') {
  // Delegate to auth.js
  const { execSync } = await import('child_process');
  execSync('node auth.js', { stdio: 'inherit', cwd: import.meta.dirname });
  process.exit(0);
}

if (!TOKEN) {
  console.error('Not authenticated. Run: eval $(node auth.js --export)');
  process.exit(1);
}

const headers = {
  Authorization: `Bearer ${TOKEN}`,
  'Content-Type': 'application/json',
};

async function api(method, path, body) {
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);

  const res = await fetch(`${LOCKSMITH_URL}${path}`, opts);
  const data = await res.json();

  if (!res.ok) {
    console.error(`Error ${res.status}:`, data.error || JSON.stringify(data));
    process.exit(1);
  }

  return data;
}

function print(data) {
  console.log(JSON.stringify(data, null, 2));
}

// Command routing
switch (cmd) {
  case 'status':
    print(await api('GET', '/status'));
    break;

  case 'nonce': {
    const [service, ...scopeParts] = args;
    if (!service) { console.error('Usage: locksmith nonce <service> <scope>'); process.exit(1); }
    print(await api('POST', '/nonce', { service, scope: scopeParts.join(' ') || '*' }));
    break;
  }

  case 'rotate': {
    const [service, target] = args;
    if (!service || !target) { console.error('Usage: locksmith rotate <service> <target>'); process.exit(1); }
    print(await api('POST', `/rotate/${service}`, { target, userName: target }));
    break;
  }

  case 'tls': {
    const [subcmd, ...subargs] = args;
    switch (subcmd) {
      case 'status':
        if (subargs[0]) {
          print(await api('GET', `/tls/status/${subargs[0]}`));
        } else {
          print(await api('GET', '/tls/status'));
        }
        break;
      case 'issue': {
        const env = subargs[0];
        const force = subargs.includes('--force');
        if (!env) { console.error('Usage: locksmith tls issue <env> [--force]'); process.exit(1); }
        print(await api('POST', `/tls/issue/${env}`, { force }));
        break;
      }
      case 'push-acm': {
        const env = subargs[0];
        const region = subargs[1];
        if (!env) { console.error('Usage: locksmith tls push-acm <env> [region]'); process.exit(1); }
        print(await api('POST', `/tls/push/acm/${env}`, { region }));
        break;
      }
      case 'push-servers': {
        const env = subargs[0];
        const ids = subargs[1]?.split(',');
        if (!env || !ids) { console.error('Usage: locksmith tls push-servers <env> <id1,id2,...>'); process.exit(1); }
        print(await api('POST', `/tls/push/servers/${env}`, { instanceIds: ids }));
        break;
      }
      case 'renew-all':
        print(await api('POST', '/tls/renew-all'));
        break;
      default:
        console.error('Unknown tls subcommand. Try: status, issue, push-acm, push-servers, renew-all');
        process.exit(1);
    }
    break;
  }

  case 'ssh': {
    const [subcmd, ...subargs] = args;
    if (subcmd === 'cert') {
      const principals = subargs[0]?.split(',') || ['deploy'];
      const result = await api('POST', '/ssh/cert', { principals });
      // Don't pretty-print the whole thing - just show the useful bits
      console.log(`Key ID:     ${result.keyId}`);
      console.log(`Principals: ${result.principals.join(', ')}`);
      console.log(`Expires:    ${result.expiresAt}`);
      console.log(`\nAdd to agent:\n  ${result.usage.addToAgent}`);
    } else if (subcmd === 'ca') {
      const pubkey = await api('GET', '/ssh/ca');
      console.log(typeof pubkey === 'string' ? pubkey : JSON.stringify(pubkey));
    } else if (subcmd === 'setup') {
      print(await api('GET', '/ssh/setup'));
    } else {
      console.error('Usage: locksmith ssh cert [principals] | locksmith ssh ca | locksmith ssh setup');
      process.exit(1);
    }
    break;
  }

  default:
    console.error(`Unknown command: ${cmd}. Run 'locksmith help' for usage.`);
    process.exit(1);
}
