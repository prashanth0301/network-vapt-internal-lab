export const USERNAME_PATTERN = /^[a-zA-Z0-9_]{3,32}$/;
export const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
export const MIN_PASSWORD_LENGTH = 8;
export const MAX_FIELD_LENGTH = 255;

export function validateUsername(value: string): string | null {
  if (!value.trim()) return 'Username is required';
  if (!USERNAME_PATTERN.test(value)) {
    return 'Username must be 3-32 characters (letters, numbers, underscores)';
  }
  return null;
}

export function validateEmail(value: string): string | null {
  if (!value.trim()) return 'Email is required';
  if (!EMAIL_PATTERN.test(value.trim())) return 'Enter a valid email address';
  if (value.length > MAX_FIELD_LENGTH) return 'Email is too long';
  return null;
}

export function validateFullName(value: string): string | null {
  if (value && value.length > MAX_FIELD_LENGTH) return 'Full name is too long';
  return null;
}

export function validatePassword(value: string): string | null {
  if (!value) return 'Password is required';
  if (value.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
  }
  if (value.length > 128) return 'Password is too long';
  return null;
}

export function validatePasswordConfirm(password: string, confirm: string): string | null {
  if (!confirm) return 'Please confirm the password';
  if (password !== confirm) return 'Passwords do not match';
  return null;
}

export function validateRole(value: string): string | null {
  if (!value) return 'Role is required';
  if (!['administrator', 'security_analyst', 'viewer'].includes(value)) {
    return 'Invalid role selected';
  }
  return null;
}
