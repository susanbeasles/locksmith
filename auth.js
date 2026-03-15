#!/usr/bin/env node

// Locksmith CLI Auth Helper
// Gets an Entra ID token via device code flow (no browser redirect needed)
// Usage: node auth.js
// Or:    eval $(node auth.js --export)

const TENANT_ID = process.env.ENTRA_TENANT_ID;
const CLIENT_ID = process.env.ENTRA_CLIENT_ID;
const LOCKSMITH_URL = process.env.LOCKSMITH_URL || 'http://localhost:3100';

if (!TENANT_ID || !CLIENT_ID) {
  console.error('Set ENTRA_TENANT_ID and ENTRA_CLIENT_ID environment variables');
  console.error('Or run via: op run --env-file .env.locksmith -- node auth.js');
  process.exit(1);
}

const exportMode = process.argv.includes('--export');
const scope = `${CLIENT_ID}/.default openid profile email`;

async function deviceCodeFlow() {
  // Step 1: Request device code
  const codeRes = await fetch(
    `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/devicecode`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CLIENT_ID, scope }),
    }
  );

  const codeData = await codeRes.json();

  if (codeData.error) {
    console.error('Device code request failed:', codeData.error_description);
    process.exit(1);
  }

  // Step 2: Show the user code and URL
  if (!exportMode) {
    console.log('\n  ╔═══════════════════════════════════════╗');
    console.log('  ║       LOCKSMITH AUTHENTICATION        ║');
    console.log('  ╠═══════════════════════════════════════╣');
    console.log(`  ║  Go to: ${codeData.verification_uri.padEnd(28)}║`);
    console.log(`  ║  Enter: ${codeData.user_code.padEnd(28)}║`);
    console.log('  ╚═══════════════════════════════════════╝\n');
    console.log('  Waiting for authentication...\n');
  } else {
    console.error(`Go to ${codeData.verification_uri} and enter code: ${codeData.user_code}`);
  }

  // Step 3: Poll for token
  const interval = codeData.interval || 5;
  const expiresAt = Date.now() + (codeData.expires_in * 1000);

  while (Date.now() < expiresAt) {
    await new Promise(r => setTimeout(r, interval * 1000));

    const tokenRes = await fetch(
      `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: CLIENT_ID,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: codeData.device_code,
        }),
      }
    );

    const tokenData = await tokenRes.json();

    if (tokenData.error === 'authorization_pending') {
      continue;
    }

    if (tokenData.error === 'slow_down') {
      await new Promise(r => setTimeout(r, 5000));
      continue;
    }

    if (tokenData.error) {
      console.error('Authentication failed:', tokenData.error_description);
      process.exit(1);
    }

    // Success
    if (exportMode) {
      // Output as shell export for eval $(node auth.js --export)
      console.log(`export LOCKSMITH_TOKEN="${tokenData.access_token}"`);
      console.log(`export LOCKSMITH_URL="${LOCKSMITH_URL}"`);
    } else {
      console.log('  Authenticated successfully.\n');

      // Decode the token to show identity (without verification, just for display)
      const payload = JSON.parse(
        Buffer.from(tokenData.access_token.split('.')[1], 'base64').toString()
      );

      console.log(`  User:    ${payload.name || payload.preferred_username}`);
      console.log(`  Email:   ${payload.preferred_username || payload.email}`);
      console.log(`  Expires: ${new Date(payload.exp * 1000).toLocaleString()}`);
      console.log(`  Groups:  ${(payload.groups || []).length} group(s)\n`);

      // Quick test against Locksmith
      console.log('  Testing Locksmith connection...');
      try {
        const statusRes = await fetch(`${LOCKSMITH_URL}/status`, {
          headers: { Authorization: `Bearer ${tokenData.access_token}` },
        });
        const status = await statusRes.json();
        console.log(`  Locksmith status: ${status.status}\n`);
      } catch {
        console.log(`  Locksmith not reachable at ${LOCKSMITH_URL} (that's fine for now)\n`);
      }

      console.log('  Token (use as Authorization: Bearer <token>):');
      console.log(`  ${tokenData.access_token.substring(0, 50)}...`);
      console.log(`\n  Or run: eval $(node auth.js --export)\n`);
    }

    return;
  }

  console.error('Authentication timed out');
  process.exit(1);
}

deviceCodeFlow().catch(err => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
