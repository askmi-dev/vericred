import { describe, it, expect } from 'vitest';
import { maskEmail, maskName, maskHolderRecord, maskCredentialRecord } from '../masking.js';

describe('Administrative PII-Masking Helpers', () => {
  describe('maskEmail', () => {
    it('masks standard email addresses correctly', () => {
      expect(maskEmail('alice@example.com')).toBe('al***@example.com');
      expect(maskEmail('bob.smith@company.org')).toBe('bo***@company.org');
    });

    it('handles short local parts gracefully', () => {
      expect(maskEmail('a@domain.com')).toBe('a***@domain.com');
      expect(maskEmail('ab@domain.com')).toBe('a***@domain.com');
    });

    it('returns asterisks for invalid email inputs', () => {
      expect(maskEmail('not-an-email')).toBe('***');
      expect(maskEmail(null)).toBe('***');
      expect(maskEmail(12345)).toBe('***');
    });
  });

  describe('maskName', () => {
    it('masks names correctly', () => {
      expect(maskName('Alice Muster')).toBe('Al*** Mu***');
      expect(maskName('John')).toBe('Jo***');
    });

    it('handles short names gracefully', () => {
      expect(maskName('Li')).toBe('L***');
      expect(maskName('A')).toBe('A***');
    });

    it('returns empty string for empty inputs', () => {
      expect(maskName('')).toBe('');
      expect(maskName(null)).toBe('');
    });
  });

  describe('maskHolderRecord', () => {
    it('masks all PII and completely strips password fields', () => {
      const holder = {
        id: 'holder-123',
        firstName: 'Emma',
        lastName: 'Schulz',
        email: 'emma.schulz@example.com',
        dateOfBirth: '2000-01-01',
        defaultPassword: 'secure-pwd-1',
        customPassword: 'secure-pwd-2',
        region: 'Tyrol'
      };

      const masked = maskHolderRecord(holder);

      expect(masked.id).toBe('holder-123');
      expect(masked.firstName).toBe('Em***');
      expect(masked.lastName).toBe('Sc***');
      expect(masked.email).toBe('em***@example.com');
      expect(masked.dateOfBirth).toBe('****-**-**');
      expect(masked.region).toBe('Tyrol');
      expect(masked.defaultPassword).toBeUndefined();
      expect(masked.customPassword).toBeUndefined();
    });
  });

  describe('maskCredentialRecord', () => {
    it('masks holderEmail in credential records', () => {
      const cred = {
        credentialId: 'urn:uuid:123',
        holderEmail: 'emma@example.com',
        statusIndex: 5,
        revoked: false
      };

      const masked = maskCredentialRecord(cred);

      expect(masked.credentialId).toBe('urn:uuid:123');
      expect(masked.holderEmail).toBe('em***@example.com');
      expect(masked.statusIndex).toBe(5);
    });
  });
});
