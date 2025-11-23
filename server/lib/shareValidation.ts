/**
 * Share Link Validation and Security
 *
 * Additional validation and security checks for share operations:
 * - Input sanitization
 * - XSS prevention
 * - SQL injection prevention (handled by Prisma)
 * - Malicious input detection
 */

import { z } from 'zod';
import DOMPurify from 'isomorphic-dompurify';

/**
 * Sanitize string input to prevent XSS
 * Uses DOMPurify to strip all HTML tags and dangerous content
 */
export function sanitizeString(input: string): string {
  // Use DOMPurify to remove all HTML tags and dangerous content
  const sanitized = DOMPurify.sanitize(input, {
    ALLOWED_TAGS: [], // Strip all HTML tags
    ALLOWED_ATTR: [], // Strip all attributes
    KEEP_CONTENT: true, // Keep text content
  });

  return sanitized.trim();
}

/**
 * Validate IP address format
 */
export function isValidIP(ip: string): boolean {
  // IPv4
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.');
    return parts.every((part) => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255;
    });
  }

  // IPv6 (simplified check)
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv6Regex.test(ip);
}

/**
 * Validate email format with additional security checks
 */
export function validateEmail(email: string): { valid: boolean; error?: string } {
  // Basic format check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { valid: false, error: 'Invalid email format' };
  }

  // Check for suspicious patterns
  const suspiciousPatterns = [
    /javascript:/i,
    /<script/i,
    /on\w+=/i,
    /data:text\/html/i,
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(email)) {
      return { valid: false, error: 'Email contains invalid characters' };
    }
  }

  // Check length
  if (email.length > 254) {
    return { valid: false, error: 'Email too long' };
  }

  return { valid: true };
}

/**
 * Validate name input with sanitization
 */
export function validateName(
  name: string,
  minLength: number = 2,
  maxLength: number = 50
): { valid: boolean; sanitized?: string; error?: string } {
  // Check length
  if (name.length < minLength) {
    return { valid: false, error: `Name must be at least ${minLength} characters` };
  }

  if (name.length > maxLength) {
    return { valid: false, error: `Name must be at most ${maxLength} characters` };
  }

  // Sanitize
  const sanitized = sanitizeString(name);

  // Check for empty after sanitization
  if (sanitized.length === 0) {
    return { valid: false, error: 'Name contains only invalid characters' };
  }

  // Check for reasonable content (at least one letter or number)
  if (!/[a-zA-Z0-9]/.test(sanitized)) {
    return { valid: false, error: 'Name must contain at least one letter or number' };
  }

  return { valid: true, sanitized };
}

/**
 * Validate reason/message input
 */
export function validateMessage(
  message: string,
  maxLength: number = 500
): { valid: boolean; sanitized?: string; error?: string } {
  if (message.length > maxLength) {
    return { valid: false, error: `Message must be at most ${maxLength} characters` };
  }

  const sanitized = sanitizeString(message);

  return { valid: true, sanitized };
}

/**
 * Validate organization input
 */
export function validateOrganization(
  organization: string,
  maxLength: number = 100
): { valid: boolean; sanitized?: string; error?: string } {
  if (organization.length > maxLength) {
    return { valid: false, error: `Organization name must be at most ${maxLength} characters` };
  }

  const sanitized = sanitizeString(organization);

  return { valid: true, sanitized };
}

/**
 * Check for common malicious patterns in any input
 */
export function detectMaliciousInput(input: string): boolean {
  const maliciousPatterns = [
    // Script injection
    /<script/i,
    /<iframe/i,
    /<object/i,
    /<embed/i,

    // Event handlers
    /on\w+\s*=/i,

    // Data URLs
    /data:text\/html/i,
    /data:application\/javascript/i,

    // JavaScript protocol
    /javascript:/i,
    /vbscript:/i,

    // SQL injection patterns (defense in depth, Prisma handles this)
    /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)/i,

    // Path traversal
    /\.\.\//,
    /\.\.\\/,
  ];

  return maliciousPatterns.some((pattern) => pattern.test(input));
}

/**
 * Validate and sanitize join request data
 */
export function validateJoinRequestData(data: {
  name: string;
  email?: string;
  reason?: string;
  organization?: string;
  password?: string;
  nameMinLength?: number;
  nameMaxLength?: number;
}): {
  valid: boolean;
  sanitized?: {
    name: string;
    email?: string;
    reason?: string;
    organization?: string;
    password?: string;
  };
  error?: string;
} {
  // Validate name
  const nameValidation = validateName(
    data.name,
    data.nameMinLength || 2,
    data.nameMaxLength || 50
  );

  if (!nameValidation.valid) {
    return { valid: false, error: nameValidation.error };
  }

  const result: any = {
    name: nameValidation.sanitized,
  };

  // Validate email if provided
  if (data.email) {
    // Check for malicious patterns first
    if (detectMaliciousInput(data.email)) {
      return { valid: false, error: 'Email contains invalid characters' };
    }

    const emailValidation = validateEmail(data.email);
    if (!emailValidation.valid) {
      return { valid: false, error: emailValidation.error };
    }

    result.email = data.email.toLowerCase().trim();
  }

  // Validate reason if provided
  if (data.reason) {
    if (detectMaliciousInput(data.reason)) {
      return { valid: false, error: 'Reason contains invalid characters' };
    }

    const reasonValidation = validateMessage(data.reason, 500);
    if (!reasonValidation.valid) {
      return { valid: false, error: reasonValidation.error };
    }

    result.reason = reasonValidation.sanitized;
  }

  // Validate organization if provided
  if (data.organization) {
    if (detectMaliciousInput(data.organization)) {
      return { valid: false, error: 'Organization name contains invalid characters' };
    }

    const orgValidation = validateOrganization(data.organization, 100);
    if (!orgValidation.valid) {
      return { valid: false, error: orgValidation.error };
    }

    result.organization = orgValidation.sanitized;
  }

  // Password validation (no sanitization, preserve exact value)
  if (data.password !== undefined) {
    if (data.password.length > 100) {
      return { valid: false, error: 'Password too long' };
    }
    result.password = data.password;
  }

  return { valid: true, sanitized: result };
}

/**
 * Validate IP address list
 */
export function validateIPList(ips: string[]): { valid: boolean; error?: string } {
  if (ips.length > 100) {
    return { valid: false, error: 'Too many IP addresses (max 100)' };
  }

  for (const ip of ips) {
    if (!isValidIP(ip)) {
      return { valid: false, error: `Invalid IP address: ${ip}` };
    }
  }

  return { valid: true };
}

/**
 * Validate share code format
 */
export function validateShareCode(shareCode: string): { valid: boolean; error?: string } {
  // Share codes should be alphanumeric and 6-16 characters
  const shareCodeRegex = /^[a-zA-Z0-9]{6,16}$/;

  if (!shareCodeRegex.test(shareCode)) {
    return {
      valid: false,
      error: 'Invalid share code format',
    };
  }

  return { valid: true };
}
