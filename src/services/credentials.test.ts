import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockSmSend, mockKmsSend } = vi.hoisted(() => ({
  mockSmSend: vi.fn(),
  mockKmsSend: vi.fn(),
}));

vi.mock('@aws-sdk/client-secrets-manager', () => {
  class MockSecretsManagerClient {
    send = mockSmSend;
  }
  class GetSecretValueCommand {
    constructor(public input: unknown) {}
  }
  return { SecretsManagerClient: MockSecretsManagerClient, GetSecretValueCommand };
});

vi.mock('@aws-sdk/client-kms', () => {
  class MockKMSClient {
    send = mockKmsSend;
  }
  class EncryptCommand {
    constructor(public input: unknown) {}
  }
  class DecryptCommand {
    constructor(public input: unknown) {}
  }
  return { KMSClient: MockKMSClient, EncryptCommand, DecryptCommand };
});

vi.mock('../config.js', () => ({
  config: {
    aws: { region: 'us-east-1' },
    kms: { keyId: 'test-kms-key-id' },
  },
}));

vi.mock('../utils/audit.js', () => ({
  logAuditEvent: vi.fn(),
  credentialFingerprint: vi.fn().mockReturnValue('sha256:abcdef1234567890'),
}));

import {
  resolveCredential,
  invalidateCache,
  envelopeEncrypt,
  envelopeDecrypt,
} from './credentials.js';

describe('credentials service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invalidateCache();
  });

  describe('resolveCredential', () => {
    it('resolves a credential from Secrets Manager', async () => {
      mockSmSend.mockResolvedValueOnce({
        SecretString: JSON.stringify({ token: 'test-token' }),
      });

      const result = await resolveCredential('github');

      expect(result).toEqual({ token: 'test-token' });
      expect(mockSmSend).toHaveBeenCalledTimes(1);
    });

    it('returns cached credential on second call', async () => {
      mockSmSend.mockResolvedValueOnce({
        SecretString: JSON.stringify({ token: 'cached-token' }),
      });

      const first = await resolveCredential('slack');
      const second = await resolveCredential('slack');

      expect(first).toEqual(second);
      expect(mockSmSend).toHaveBeenCalledTimes(1);
    });

    it('throws for unknown service', async () => {
      await expect(resolveCredential('nonexistent')).rejects.toThrow(
        'No credential source configured for service: nonexistent',
      );
    });

    it('throws when secret has no string value', async () => {
      mockSmSend.mockResolvedValueOnce({ SecretString: undefined });

      await expect(resolveCredential('github')).rejects.toThrow('no string value');
    });

    it('wraps non-JSON secret as { value: string }', async () => {
      mockSmSend.mockResolvedValueOnce({
        SecretString: 'plain-text-secret',
      });

      const result = await resolveCredential('sentry');

      expect(result).toEqual({ value: 'plain-text-secret' });
    });

    it('invalidateCache forces re-fetch', async () => {
      mockSmSend.mockResolvedValueOnce({
        SecretString: JSON.stringify({ token: 'v1' }),
      });
      mockSmSend.mockResolvedValueOnce({
        SecretString: JSON.stringify({ token: 'v2' }),
      });

      const first = await resolveCredential('jira');
      invalidateCache('jira');
      const second = await resolveCredential('jira');

      expect(first).toEqual({ token: 'v1' });
      expect(second).toEqual({ token: 'v2' });
      expect(mockSmSend).toHaveBeenCalledTimes(2);
    });

    it('invalidateCache with no arg clears all', async () => {
      mockSmSend.mockResolvedValueOnce({
        SecretString: JSON.stringify({ token: 'a' }),
      });
      mockSmSend.mockResolvedValueOnce({
        SecretString: JSON.stringify({ token: 'b' }),
      });
      mockSmSend.mockResolvedValueOnce({
        SecretString: JSON.stringify({ token: 'a2' }),
      });
      mockSmSend.mockResolvedValueOnce({
        SecretString: JSON.stringify({ token: 'b2' }),
      });

      await resolveCredential('github');
      await resolveCredential('slack');
      invalidateCache();
      await resolveCredential('github');
      await resolveCredential('slack');

      expect(mockSmSend).toHaveBeenCalledTimes(4);
    });
  });

  describe('envelopeEncrypt', () => {
    it('encrypts plaintext with KMS', async () => {
      const ciphertext = new Uint8Array([1, 2, 3]);
      mockKmsSend.mockResolvedValueOnce({ CiphertextBlob: ciphertext });

      const result = await envelopeEncrypt('secret-data');

      expect(result.ciphertextBlob).toBe(ciphertext);
      expect(result.keyId).toBe('test-kms-key-id');
    });

    it('throws when KMS returns no ciphertext', async () => {
      mockKmsSend.mockResolvedValueOnce({ CiphertextBlob: undefined });

      await expect(envelopeEncrypt('data')).rejects.toThrow('no ciphertext');
    });
  });

  describe('envelopeDecrypt', () => {
    it('decrypts ciphertext blob', async () => {
      const plaintext = new TextEncoder().encode('decrypted-secret');
      mockKmsSend.mockResolvedValueOnce({ Plaintext: plaintext });

      const result = await envelopeDecrypt(new Uint8Array([1, 2, 3]));

      expect(result).toBe('decrypted-secret');
    });

    it('throws when KMS returns no plaintext', async () => {
      mockKmsSend.mockResolvedValueOnce({ Plaintext: undefined });

      await expect(envelopeDecrypt(new Uint8Array([1]))).rejects.toThrow('no plaintext');
    });
  });
});
