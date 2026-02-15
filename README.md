# Lab 6: Implementing Login Flow

### Week 7 — Frontend-Backend II (Authentication)

## Overview

In this lab, you'll implement a complete login flow for a **Bookmark Manager** application. You'll build JWT decoding utilities, an authentication service, a login form component, and protected content that requires authentication — all backed by thorough tests.

This lab connects directly to your Week 7 readings on JSON Web Tokens (JWT.io) and OAuth 2.0 (Aaron Parecki). You'll see how the concepts from those readings — token structure, authorization flows, and the distinction between authentication and authorization — translate into working code.

**Estimated Time:** 90–120 minutes

**Prerequisites:**
- Familiarity with React component testing (Lab 3)
- Experience connecting to APIs with `fetch` (Lab 5)
- Completion of Week 7 readings on JWT and OAuth 2.0

> [!IMPORTANT]
> **Windows Users:** Use PowerShell (not Command Prompt) for all terminal commands. Both command versions are provided where they differ.

---

## Learning Objectives

By the end of this lab, you will be able to:

1. **Decode** a JWT and explain the purpose of its three parts (header, payload, signature)
2. **Implement** a login flow that sends credentials and stores the resulting token
3. **Attach** a Bearer token to API requests for authenticated endpoints
4. **Test** authentication flows using mocked API responses and React Testing Library
5. **Handle** auth state changes in React components (login, logout, error, loading)
6. **Explain** why single-page apps should not use client secrets (connecting to Parecki's OAuth reading)

---

## Connection to Readings

### From "Introduction to JSON Web Tokens" (jwt.io):
- You'll decode actual JWTs and work with the three-part structure (header.payload.signature)
- You'll implement token expiration checking using the `exp` claim
- You'll see why the payload is readable by anyone (Base64Url encoding ≠ encryption)

### From "OAuth 2.0 Simplified" (Aaron Parecki):
- You'll implement a simplified authorization flow (credentials → token → authenticated requests)
- You'll handle the Bearer token scheme in the Authorization header
- Your reflection will address why SPAs can't use client secrets

---

## Getting Started

1. Clone your repository:
   ```bash
   git clone <your-repository-url>
   cd <your-repository-name>
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Verify the starter code works:
   ```bash
   npm test
   ```

✅ **Checkpoint:** You should see output indicating the test suite runs (some tests may be skipped or marked as TODO). TypeScript should compile without errors.

4. Verify TypeScript compilation:
   ```bash
   npm run typecheck
   ```

✅ **Checkpoint:** No TypeScript errors.

---

## Starter Code Tour

Take a moment to explore the provided files:

```
src/
├── types/
│   └── index.ts          # Type definitions (provided)
├── utils/
│   └── .gitkeep          # You'll create jwt.ts here
├── api/
│   └── .gitkeep          # You'll create authApi.ts and bookmarkApi.ts here
├── components/
│   └── .gitkeep          # You'll create LoginForm.tsx and BookmarkList.tsx here
├── __tests__/
│   └── .gitkeep          # You'll create all test files here
└── setupTests.ts         # Test setup (provided)
```

Open `src/types/index.ts` and review the type definitions. These types define the shape of your data throughout the lab:

```typescript
// src/types/index.ts (provided — do not modify)

export interface JWTHeader {
  alg: string;
  typ: string;
}

export interface JWTPayload {
  sub: string;
  username: string;
  iat: number;
  exp: number;
}

export interface AuthResponse {
  token: string;
  user: {
    id: string;
    username: string;
  };
}

export interface AuthError {
  message: string;
  status: number;
}

export interface Bookmark {
  id: string;
  title: string;
  url: string;
  tags: string[];
  createdAt: string;
}

export interface BookmarkApiResponse {
  bookmarks: Bookmark[];
  total: number;
}
```

🤔 **Reflection Question:** Look at the `JWTPayload` interface. Which fields correspond to *registered claims* vs. *private claims* as described in the JWT.io reading?

---

## Part 1: JWT Utilities (~30 minutes)

In this part, you'll build utility functions that decode and validate JWTs. This connects directly to the JWT.io reading's explanation of token structure.

### Step 1: Create the JWT utility module

Create a new file `src/utils/jwt.ts`:

```typescript
// src/utils/jwt.ts

import { JWTHeader, JWTPayload } from '../types';

/**
 * Decodes a Base64Url-encoded string.
 * JWT uses Base64Url encoding (not standard Base64) — this means
 * '+' is replaced with '-', '/' with '_', and padding '=' is removed.
 */
export function base64UrlDecode(str: string): string {
  // Replace Base64Url characters with standard Base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if needed
  const padding = base64.length % 4;
  if (padding === 2) base64 += '==';
  else if (padding === 3) base64 += '=';

  return atob(base64);
}

/**
 * Decodes the header portion of a JWT.
 * The header is the first part (before the first dot).
 */
export function decodeHeader(token: string): JWTHeader {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT: token must have exactly three parts');
  }

  try {
    const decoded = base64UrlDecode(parts[0]);
    return JSON.parse(decoded) as JWTHeader;
  } catch {
    throw new Error('Invalid JWT: unable to decode header');
  }
}

/**
 * Decodes the payload portion of a JWT.
 * The payload is the second part (between the two dots).
 *
 * IMPORTANT: As the JWT.io reading warns, decoding ≠ verification.
 * The payload is readable by anyone — this function does NOT
 * verify the signature.
 */
export function decodePayload(token: string): JWTPayload {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT: token must have exactly three parts');
  }

  try {
    const decoded = base64UrlDecode(parts[1]);
    return JSON.parse(decoded) as JWTPayload;
  } catch {
    throw new Error('Invalid JWT: unable to decode payload');
  }
}

// TODO: Implement isTokenExpired
// This function should:
// 1. Decode the token's payload
// 2. Get the 'exp' (expiration) claim
// 3. Compare it to the current time (Date.now() / 1000)
// 4. Return true if the token is expired, false otherwise
// 5. If the token is invalid, return true (treat invalid tokens as expired)
//
// Hint: The 'exp' claim is in seconds since Unix epoch.
//       Date.now() returns milliseconds — divide by 1000!
export function isTokenExpired(token: string): boolean {
  // TODO: Replace this with your implementation
  throw new Error('Not implemented');
}
```

### Step 2: Create JWT utility tests

Create `src/__tests__/jwt.test.ts`:

```typescript
// src/__tests__/jwt.test.ts

import { describe, it, expect, vi, afterEach } from 'vitest';
import { base64UrlDecode, decodeHeader, decodePayload, isTokenExpired } from '../utils/jwt';

// A valid test JWT (this is NOT a secret — JWTs are readable by anyone!)
// Header: {"alg":"HS256","typ":"JWT"}
// Payload: {"sub":"user-123","username":"alice","iat":1700000000,"exp":1700003600}
// This token expires at Unix timestamp 1700003600 (Nov 14, 2023 ~5pm UTC)
const VALID_TOKEN =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJzdWIiOiJ1c2VyLTEyMyIsInVzZXJuYW1lIjoiYWxpY2UiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMzYwMH0.' +
  'fake-signature-for-testing';

const MALFORMED_TOKEN = 'not.a.valid.jwt.token';
const TWO_PART_TOKEN = 'only-two.parts';

describe('base64UrlDecode', () => {
  it('decodes a standard Base64Url string', () => {
    // "Hello" in Base64Url
    const encoded = 'SGVsbG8';
    expect(base64UrlDecode(encoded)).toBe('Hello');
  });

  it('handles Base64Url special characters (- and _)', () => {
    // A string that would use + and / in standard Base64
    const encoded = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
    const result = base64UrlDecode(encoded);
    expect(result).toContain('alg');
  });
});

describe('decodeHeader', () => {
  it('decodes the algorithm and type from a valid JWT', () => {
    const header = decodeHeader(VALID_TOKEN);
    expect(header.alg).toBe('HS256');
    expect(header.typ).toBe('JWT');
  });

  it('throws an error for a token without three parts', () => {
    expect(() => decodeHeader(TWO_PART_TOKEN)).toThrow('Invalid JWT');
  });

  // TODO: Add a test that verifies decodeHeader throws for an empty string
});

describe('decodePayload', () => {
  it('decodes user information from a valid JWT', () => {
    const payload = decodePayload(VALID_TOKEN);
    expect(payload.sub).toBe('user-123');
    expect(payload.username).toBe('alice');
  });

  it('decodes timestamp claims from a valid JWT', () => {
    const payload = decodePayload(VALID_TOKEN);
    expect(payload.iat).toBe(1700000000);
    expect(payload.exp).toBe(1700003600);
  });

  it('throws an error for a token without three parts', () => {
    expect(() => decodePayload(TWO_PART_TOKEN)).toThrow('Invalid JWT');
  });

  // TODO: Add a test for a token with an invalid (non-JSON) payload
});

describe('isTokenExpired', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns true for an expired token', () => {
    // Mock Date.now to return a time AFTER the token's exp
    vi.spyOn(Date, 'now').mockReturnValue(1700003601 * 1000);
    expect(isTokenExpired(VALID_TOKEN)).toBe(true);
  });

  it('returns false for a non-expired token', () => {
    // Mock Date.now to return a time BEFORE the token's exp
    vi.spyOn(Date, 'now').mockReturnValue(1700000000 * 1000);
    expect(isTokenExpired(VALID_TOKEN)).toBe(false);
  });

  // TODO: Add a test that verifies isTokenExpired returns true for a malformed token

  // TODO: Add a test for a token that expires exactly at the current time (edge case)
});
```

### Step 3: Implement `isTokenExpired`

Go back to `src/utils/jwt.ts` and implement the `isTokenExpired` function. The TODO comment describes exactly what to do.

✅ **Checkpoint:** Run `npm test -- --run src/__tests__/jwt.test.ts` — all non-TODO tests should pass. Then complete the TODO tests and ensure they pass too.

🤔 **Reflection Question:** The JWT.io reading warns against putting secret information in the payload. Based on your `decodePayload` implementation, why is that advice important?

---

## Part 2: Auth Service (~30 minutes)

Now you'll build the authentication service that handles login, logout, and token management. This module acts as the "Client" in OAuth terminology — it requests access from the authorization server.

### Step 1: Create the auth API module

Create `src/api/authApi.ts`:

```typescript
// src/api/authApi.ts

import { AuthResponse, AuthError } from '../types';
import { isTokenExpired } from '../utils/jwt';

const AUTH_API_URL = 'http://localhost:3001/api/auth';

// Module-level token storage
// In a real app, you might use a more sophisticated approach,
// but for this lab we store the token in a module variable.
let currentToken: string | null = null;

/**
 * Attempts to log in with the given credentials.
 * On success, stores the token and returns the auth response.
 * On failure, throws an AuthError.
 */
export async function login(
  username: string,
  password: string
): Promise<AuthResponse> {
  const response = await fetch(`${AUTH_API_URL}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    const error: AuthError = {
      message:
        response.status === 401
          ? 'Invalid username or password'
          : 'Login failed. Please try again.',
      status: response.status,
    };
    throw error;
  }

  const data: AuthResponse = await response.json();
  currentToken = data.token;
  return data;
}

/**
 * Clears the stored token, effectively logging out the user.
 */
export function logout(): void {
  currentToken = null;
}

/**
 * Returns the currently stored token, or null if not logged in.
 */
export function getToken(): string | null {
  return currentToken;
}

// TODO: Implement isAuthenticated
// This function should:
// 1. Check if there IS a current token (return false if null)
// 2. Check if the token is expired using isTokenExpired from your jwt utils
// 3. Return true only if a token exists AND is not expired
// 4. If the token is expired, clear it by calling logout()
//
// This connects to the JWT.io reading: tokens carry their own
// expiration information, so the client can check validity locally.
export function isAuthenticated(): boolean {
  // TODO: Replace this with your implementation
  throw new Error('Not implemented');
}

// TODO: Implement getAuthHeaders
// This function should:
// 1. Get the current token
// 2. If no token exists, throw an error with message 'Not authenticated'
// 3. Return a headers object with:
//    - 'Content-Type': 'application/json'
//    - 'Authorization': 'Bearer <token>'
//
// The JWT.io reading describes this exact pattern:
// "The user agent should send the JWT, typically in the
//  Authorization header using the Bearer schema."
export function getAuthHeaders(): Record<string, string> {
  // TODO: Replace this with your implementation
  throw new Error('Not implemented');
}

/**
 * Resets the module state. Used in tests to ensure clean state
 * between test cases.
 */
export function _resetForTesting(): void {
  currentToken = null;
}
```

### Step 2: Create auth API tests

Create `src/__tests__/authApi.test.ts`:

```typescript
// src/__tests__/authApi.test.ts

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  login,
  logout,
  getToken,
  isAuthenticated,
  getAuthHeaders,
  _resetForTesting,
} from '../api/authApi';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// A test token with expiration far in the future
const FUTURE_TOKEN =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJzdWIiOiJ1c2VyLTEyMyIsInVzZXJuYW1lIjoiYWxpY2UiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0.' +
  'fake-signature';

// A test token that is already expired
const EXPIRED_TOKEN =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJzdWIiOiJ1c2VyLTEyMyIsInVzZXJuYW1lIjoiYWxpY2UiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTAwMDAwMDAwMH0.' +
  'fake-signature';

const mockAuthResponse = {
  token: FUTURE_TOKEN,
  user: { id: 'user-123', username: 'alice' },
};

describe('login', () => {
  beforeEach(() => {
    _resetForTesting();
    mockFetch.mockReset();
  });

  it('sends credentials and stores the token on success', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockAuthResponse,
    });

    const result = await login('alice', 'password123');

    // Verify fetch was called correctly
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:3001/api/auth/login',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'alice', password: 'password123' }),
      })
    );

    // Verify response
    expect(result.user.username).toBe('alice');
    expect(result.token).toBe(FUTURE_TOKEN);

    // Verify token was stored
    expect(getToken()).toBe(FUTURE_TOKEN);
  });

  it('throws an error with message for invalid credentials (401)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
    });

    await expect(login('alice', 'wrong')).rejects.toEqual(
      expect.objectContaining({
        message: 'Invalid username or password',
        status: 401,
      })
    );
  });

  it('throws a generic error for server errors (500)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    await expect(login('alice', 'password123')).rejects.toEqual(
      expect.objectContaining({
        message: 'Login failed. Please try again.',
        status: 500,
      })
    );
  });

  // TODO: Add a test that verifies the token is NOT stored when login fails
});

describe('logout', () => {
  beforeEach(() => {
    _resetForTesting();
    mockFetch.mockReset();
  });

  it('clears the stored token', async () => {
    // First, log in to set a token
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockAuthResponse,
    });
    await login('alice', 'password123');
    expect(getToken()).toBe(FUTURE_TOKEN);

    // Now logout
    logout();
    expect(getToken()).toBeNull();
  });
});

describe('isAuthenticated', () => {
  beforeEach(() => {
    _resetForTesting();
    mockFetch.mockReset();
  });

  it('returns false when no token is stored', () => {
    expect(isAuthenticated()).toBe(false);
  });

  it('returns true when a valid (non-expired) token is stored', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockAuthResponse,
    });
    await login('alice', 'password123');

    expect(isAuthenticated()).toBe(true);
  });

  // TODO: Add a test that verifies isAuthenticated returns false
  //       when the stored token is expired, AND that it clears the token

  // TODO: Add a test using an expired token (EXPIRED_TOKEN) — log in
  //       with a mock response containing EXPIRED_TOKEN, then verify
  //       isAuthenticated returns false
});

describe('getAuthHeaders', () => {
  beforeEach(() => {
    _resetForTesting();
    mockFetch.mockReset();
  });

  it('returns headers with Bearer token when authenticated', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockAuthResponse,
    });
    await login('alice', 'password123');

    const headers = getAuthHeaders();
    expect(headers['Authorization']).toBe(`Bearer ${FUTURE_TOKEN}`);
    expect(headers['Content-Type']).toBe('application/json');
  });

  // TODO: Add a test that verifies getAuthHeaders throws 'Not authenticated'
  //       when no token is stored
});
```

### Step 3: Implement the TODO functions

Go back to `src/api/authApi.ts` and implement:
1. `isAuthenticated()` — checks for a valid, non-expired token
2. `getAuthHeaders()` — returns headers with the Bearer token

✅ **Checkpoint:** Run `npm test -- --run src/__tests__/authApi.test.ts` — all non-TODO tests should pass. Complete the TODO tests and verify.

---

## Part 3: Login Form Component (~25 minutes)

Now you'll build a React component for the login form. This is where authentication becomes visible to the user.

### Step 1: Create the LoginForm component

Create `src/components/LoginForm.tsx`:

```tsx
// src/components/LoginForm.tsx

import React, { useState } from 'react';
import { login } from '../api/authApi';
import { AuthResponse } from '../types';

interface LoginFormProps {
  onLoginSuccess: (response: AuthResponse) => void;
}

export function LoginForm({ onLoginSuccess }: LoginFormProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const response = await login(username, password);
      onLoginSuccess(response);
    } catch (err: unknown) {
      const authErr = err as { message: string };
      setError(authErr.message || 'An unexpected error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div>
      <h2>Sign In</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="username">Username</label>
          <input
            id="username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            disabled={isLoading}
          />
        </div>
        <div>
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            disabled={isLoading}
          />
        </div>
        {error && <p role="alert">{error}</p>}
        <button type="submit" disabled={isLoading}>
          {isLoading ? 'Signing in...' : 'Sign In'}
        </button>
      </form>
    </div>
  );
}
```

### Step 2: Create LoginForm tests

Create `src/__tests__/LoginForm.test.tsx`:

```tsx
// src/__tests__/LoginForm.test.tsx

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LoginForm } from '../components/LoginForm';

// Mock the authApi module
vi.mock('../api/authApi', () => ({
  login: vi.fn(),
}));

import { login } from '../api/authApi';
const mockLogin = vi.mocked(login);

describe('LoginForm', () => {
  const mockOnLoginSuccess = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders username and password fields with labels', () => {
    render(<LoginForm onLoginSuccess={mockOnLoginSuccess} />);

    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
  });

  it('renders a sign in button', () => {
    render(<LoginForm onLoginSuccess={mockOnLoginSuccess} />);

    expect(
      screen.getByRole('button', { name: /sign in/i })
    ).toBeInTheDocument();
  });

  it('calls login with entered credentials on form submission', async () => {
    const user = userEvent.setup();
    mockLogin.mockResolvedValueOnce({
      token: 'test-token',
      user: { id: '1', username: 'alice' },
    });

    render(<LoginForm onLoginSuccess={mockOnLoginSuccess} />);

    await user.type(screen.getByLabelText(/username/i), 'alice');
    await user.type(screen.getByLabelText(/password/i), 'password123');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(mockLogin).toHaveBeenCalledWith('alice', 'password123');
  });

  it('calls onLoginSuccess with the response on successful login', async () => {
    const user = userEvent.setup();
    const mockResponse = {
      token: 'test-token',
      user: { id: '1', username: 'alice' },
    };
    mockLogin.mockResolvedValueOnce(mockResponse);

    render(<LoginForm onLoginSuccess={mockOnLoginSuccess} />);

    await user.type(screen.getByLabelText(/username/i), 'alice');
    await user.type(screen.getByLabelText(/password/i), 'password123');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(mockOnLoginSuccess).toHaveBeenCalledWith(mockResponse);
  });

  it('displays an error message when login fails', async () => {
    const user = userEvent.setup();
    mockLogin.mockRejectedValueOnce({
      message: 'Invalid username or password',
      status: 401,
    });

    render(<LoginForm onLoginSuccess={mockOnLoginSuccess} />);

    await user.type(screen.getByLabelText(/username/i), 'alice');
    await user.type(screen.getByLabelText(/password/i), 'wrong');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Invalid username or password'
    );
  });

  it('shows loading state while login is in progress', async () => {
    const user = userEvent.setup();
    // Create a login that doesn't resolve immediately
    let resolveLogin: (value: unknown) => void;
    mockLogin.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveLogin = resolve;
      })
    );

    render(<LoginForm onLoginSuccess={mockOnLoginSuccess} />);

    await user.type(screen.getByLabelText(/username/i), 'alice');
    await user.type(screen.getByLabelText(/password/i), 'password123');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    // Button should show loading text
    expect(
      screen.getByRole('button', { name: /signing in/i })
    ).toBeDisabled();

    // Resolve the login
    resolveLogin!({
      token: 'test-token',
      user: { id: '1', username: 'alice' },
    });
  });

  // TODO: Add a test that verifies the form inputs are disabled while loading

  // TODO: Add a test that verifies the error message clears when
  //       the user submits the form again (after a previous failure)
});
```

✅ **Checkpoint:** Run `npm test -- --run src/__tests__/LoginForm.test.tsx` — all provided tests should pass. Complete the TODO tests.

🤔 **Reflection Question:** Why do we mock the `authApi` module rather than making real API calls in our component tests? How does this connect to the Testing Library guiding principle of testing *behavior* rather than *implementation*?

---

## Part 4: Protected Content (~25 minutes)

In this final part, you'll build a component that only shows content when the user is authenticated. This demonstrates the full auth flow: login → store token → use token for API access.

### Step 1: Create the Bookmark API module

Create `src/api/bookmarkApi.ts`:

```typescript
// src/api/bookmarkApi.ts

import { BookmarkApiResponse } from '../types';
import { getAuthHeaders, isAuthenticated } from './authApi';

const BOOKMARK_API_URL = 'http://localhost:3001/api/bookmarks';

/**
 * Fetches the authenticated user's bookmarks.
 * Requires a valid auth token — includes the Bearer token in the request.
 *
 * This demonstrates the pattern from the JWT.io reading:
 * "The user agent should send the JWT, typically in the
 *  Authorization header using the Bearer schema."
 */
export async function fetchBookmarks(): Promise<BookmarkApiResponse> {
  if (!isAuthenticated()) {
    throw new Error('Authentication required');
  }

  const response = await fetch(BOOKMARK_API_URL, {
    method: 'GET',
    headers: getAuthHeaders(),
  });

  if (response.status === 401) {
    throw new Error('Session expired. Please log in again.');
  }

  if (!response.ok) {
    throw new Error('Failed to fetch bookmarks');
  }

  return response.json();
}

// TODO: Implement addBookmark
// This function should:
// 1. Check isAuthenticated() — throw 'Authentication required' if not
// 2. Send a POST request to BOOKMARK_API_URL with:
//    - method: 'POST'
//    - headers: getAuthHeaders()
//    - body: JSON.stringify({ title, url, tags })
// 3. Handle 401 response: throw 'Session expired. Please log in again.'
// 4. Handle other errors: throw 'Failed to add bookmark'
// 5. Return the parsed JSON response as a Bookmark
//
// Parameters: title: string, url: string, tags: string[]
// Returns: Promise<Bookmark>
import { Bookmark } from '../types';

export async function addBookmark(
  title: string,
  url: string,
  tags: string[]
): Promise<Bookmark> {
  // TODO: Replace this with your implementation
  throw new Error('Not implemented');
}
```

### Step 2: Create the BookmarkList component

Create `src/components/BookmarkList.tsx`:

```tsx
// src/components/BookmarkList.tsx

import React, { useState, useEffect } from 'react';
import { fetchBookmarks } from '../api/bookmarkApi';
import { Bookmark } from '../types';

export function BookmarkList() {
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadBookmarks() {
      try {
        const response = await fetchBookmarks();
        setBookmarks(response.bookmarks);
      } catch (err: unknown) {
        const e = err as Error;
        setError(e.message || 'Failed to load bookmarks');
      } finally {
        setLoading(false);
      }
    }

    loadBookmarks();
  }, []);

  if (loading) {
    return <p>Loading bookmarks...</p>;
  }

  if (error) {
    return (
      <div role="alert">
        <p>{error}</p>
      </div>
    );
  }

  if (bookmarks.length === 0) {
    return <p>No bookmarks yet. Start adding some!</p>;
  }

  return (
    <div>
      <h2>My Bookmarks</h2>
      <ul>
        {bookmarks.map((bookmark) => (
          <li key={bookmark.id}>
            <a href={bookmark.url} target="_blank" rel="noopener noreferrer">
              {bookmark.title}
            </a>
            {bookmark.tags.length > 0 && (
              <span> — {bookmark.tags.join(', ')}</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
```

### Step 3: Create BookmarkList and bookmarkApi tests

Create `src/__tests__/bookmarkApi.test.ts`:

```typescript
// src/__tests__/bookmarkApi.test.ts

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fetchBookmarks, addBookmark } from '../api/bookmarkApi';

// Mock the authApi module
vi.mock('../api/authApi', () => ({
  isAuthenticated: vi.fn(),
  getAuthHeaders: vi.fn(),
}));

import { isAuthenticated, getAuthHeaders } from '../api/authApi';
const mockIsAuthenticated = vi.mocked(isAuthenticated);
const mockGetAuthHeaders = vi.mocked(getAuthHeaders);

// Mock fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

const mockBookmarkResponse = {
  bookmarks: [
    {
      id: '1',
      title: 'Vitest Docs',
      url: 'https://vitest.dev',
      tags: ['testing', 'docs'],
      createdAt: '2026-01-15T10:00:00Z',
    },
    {
      id: '2',
      title: 'React Docs',
      url: 'https://react.dev',
      tags: ['react', 'docs'],
      createdAt: '2026-01-16T10:00:00Z',
    },
  ],
  total: 2,
};

describe('fetchBookmarks', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws an error when not authenticated', async () => {
    mockIsAuthenticated.mockReturnValue(false);
    await expect(fetchBookmarks()).rejects.toThrow('Authentication required');
  });

  it('fetches bookmarks with auth headers when authenticated', async () => {
    mockIsAuthenticated.mockReturnValue(true);
    mockGetAuthHeaders.mockReturnValue({
      'Content-Type': 'application/json',
      Authorization: 'Bearer test-token',
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => mockBookmarkResponse,
    });

    const result = await fetchBookmarks();

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:3001/api/bookmarks',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer test-token',
        }),
      })
    );
    expect(result.bookmarks).toHaveLength(2);
  });

  it('throws a session expired error on 401 response', async () => {
    mockIsAuthenticated.mockReturnValue(true);
    mockGetAuthHeaders.mockReturnValue({
      'Content-Type': 'application/json',
      Authorization: 'Bearer expired-token',
    });
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
    });

    await expect(fetchBookmarks()).rejects.toThrow(
      'Session expired. Please log in again.'
    );
  });

  // TODO: Add a test for a non-401 error response (e.g., 500)
});

describe('addBookmark', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // TODO: Add a test that verifies addBookmark throws when not authenticated

  // TODO: Add a test that verifies addBookmark sends a POST request
  //       with the correct body and auth headers

  // TODO: Add a test that verifies addBookmark handles a 401 response
});
```

Create `src/__tests__/BookmarkList.test.tsx`:

```tsx
// src/__tests__/BookmarkList.test.tsx

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BookmarkList } from '../components/BookmarkList';

// Mock the bookmarkApi module
vi.mock('../api/bookmarkApi', () => ({
  fetchBookmarks: vi.fn(),
}));

import { fetchBookmarks } from '../api/bookmarkApi';
const mockFetchBookmarks = vi.mocked(fetchBookmarks);

describe('BookmarkList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows a loading message initially', () => {
    mockFetchBookmarks.mockReturnValue(new Promise(() => {})); // Never resolves
    render(<BookmarkList />);

    expect(screen.getByText(/loading bookmarks/i)).toBeInTheDocument();
  });

  it('renders bookmarks after successful fetch', async () => {
    mockFetchBookmarks.mockResolvedValueOnce({
      bookmarks: [
        {
          id: '1',
          title: 'Vitest Docs',
          url: 'https://vitest.dev',
          tags: ['testing'],
          createdAt: '2026-01-15T10:00:00Z',
        },
      ],
      total: 1,
    });

    render(<BookmarkList />);

    expect(await screen.findByText('Vitest Docs')).toBeInTheDocument();
  });

  it('displays an error message when fetch fails', async () => {
    mockFetchBookmarks.mockRejectedValueOnce(
      new Error('Authentication required')
    );

    render(<BookmarkList />);

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Authentication required'
    );
  });

  it('shows an empty state when no bookmarks exist', async () => {
    mockFetchBookmarks.mockResolvedValueOnce({
      bookmarks: [],
      total: 0,
    });

    render(<BookmarkList />);

    expect(
      await screen.findByText(/no bookmarks yet/i)
    ).toBeInTheDocument();
  });

  // TODO: Add a test that verifies bookmark tags are displayed

  // TODO: Add a test that verifies bookmark links have correct href and
  //       target="_blank" attributes (use getByRole('link'))
});
```

✅ **Checkpoint:** Run `npm test` — all provided tests should pass. Complete all TODO tests across all files.

---

## Deliverables

Your completed repository should contain:

```
src/
├── types/
│   └── index.ts                    # Provided — do not modify
├── utils/
│   └── jwt.ts                      # JWT decode/validation utilities
├── api/
│   ├── authApi.ts                  # Authentication service
│   └── bookmarkApi.ts              # Bookmark API (requires auth)
├── components/
│   ├── LoginForm.tsx               # Login form component
│   └── BookmarkList.tsx            # Protected bookmark list
├── __tests__/
│   ├── jwt.test.ts                 # JWT utility tests
│   ├── authApi.test.ts             # Auth API tests
│   ├── LoginForm.test.tsx          # Login form component tests
│   ├── bookmarkApi.test.ts         # Bookmark API tests
│   └── BookmarkList.test.tsx       # BookmarkList component tests
└── setupTests.ts                   # Provided — do not modify
```

### README Requirements

Update the repository's `README.md` to include:

1. **Your name** and the date
2. **Reflection** (200+ words) addressing:
   - How does the JWT structure (header.payload.signature) enable stateless authentication?
   - Why can't single-page applications use a client secret, according to Parecki?
   - What role does the Bearer token play in the Authorization header?
   - How did mocking the auth module in component tests compare to mocking `fetch` in the API tests?
3. **Key Concepts Learned** — list 3–5 concepts with brief explanations

### Quality Requirements

- ✅ Minimum **20 passing tests** (all TODOs completed + provided tests)
- ✅ Minimum **90% code coverage** across statements, branches, functions, lines
- ✅ All TypeScript compiles without errors
- ✅ No `any` types (use the provided type definitions)

---

## Grading Rubric

| Criteria | Points | Description |
|----------|--------|-------------|
| JWT utilities + tests | 20 | `jwt.ts` functions work correctly; all guided + TODO tests pass |
| Auth service + tests | 20 | `authApi.ts` TODO functions implemented; all guided + TODO tests pass |
| Login form + tests | 15 | `LoginForm.tsx` renders correctly; all guided + TODO tests pass |
| Bookmark API + BookmarkList + tests | 15 | `bookmarkApi.ts` TODO implemented; `BookmarkList.tsx` tested; all TODO tests complete |
| README with reflection (200+ words) | 10 | Thoughtful answers connecting to JWT.io and OAuth readings |
| Code quality (TypeScript, clean code, no `any`) | 10 | Proper types, meaningful names, no debug code |
| Quality metrics (90%+ coverage, 20+ tests) | 10 | Coverage threshold met; minimum test count met |
| **Total** | **100** | |

---

## Stretch Goals

If you finish early, try these extensions:

1. **Token Refresh Simulation:** Add a `refreshToken()` function that simulates requesting a new token before the current one expires. Write tests for the refresh flow.

2. **Auth Context:** Create a React Context that provides authentication state to the entire app. Wrap `LoginForm` and `BookmarkList` in a parent component that uses the context.

3. **Remember Me:** Add a "Remember me" checkbox to the login form that controls whether the token persists (you can simulate this with a boolean flag in your auth module).

---

## Troubleshooting

### "ReferenceError: atob is not defined"

**Cause:** The `atob` function is available in browsers but may not be in all Node.js versions.

**Solution:** The `setupTests.ts` file includes a polyfill for `atob`. Make sure you haven't modified it. If the issue persists, ensure you're using Node.js 20+, which includes `atob` natively.

### "TypeError: Cannot read properties of undefined (reading 'message')"

**Cause:** Your error handling isn't properly typing the caught error.

**Solution:** Use the pattern `catch (err: unknown) { const e = err as { message: string }; }` instead of `catch (err: any)`.

### Mock not working — real fetch is being called

**Cause:** The mock setup is incorrect or the module isn't being mocked properly.

**Solution:** Make sure `vi.mock(...)` is called at the top level of your test file (not inside `describe` or `it` blocks). Vitest hoists mock declarations automatically.

### Tests pass individually but fail together

**Cause:** Shared state between tests (the module-level `currentToken` variable).

**Solution:** Call `_resetForTesting()` in your `beforeEach` block to clear auth state between tests.

### Coverage below 90% despite all tests passing

**Cause:** Your TODO implementations may have branches that aren't tested, or the `addBookmark` function isn't fully covered.

**Solution:** Check the HTML coverage report (`coverage/index.html`) to see exactly which lines and branches need coverage. Make sure your TODO tests exercise all code paths.

### Warning about `@testing-library/dom` peer dependency

**Cause:** React Testing Library (v16+) requires `@testing-library/dom` as an explicit peer dependency. This is already included in your starter `package.json`.

**Solution:** Do not modify `package.json`. If you see this warning after reinstalling dependencies, run `npm ci` (not `npm install`) to restore the exact dependency tree from `package-lock.json`.

### TypeScript error: "Cannot find name 'global'"

**Cause:** Our tests run in a `jsdom` environment (simulated browser), not pure Node.js. The `global` object is a Node.js-specific reference and isn't recognized in jsdom. Many online tutorials use `global.fetch = jest.fn()` — that pattern won't work here.

**Solution:** Use one of these two approaches instead:

```typescript
// Option 1: vi.stubGlobal (recommended for mocking)
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Option 2: globalThis (ECMAScript standard, works everywhere)
globalThis.fetch = vi.fn() as unknown as typeof fetch;
```

`globalThis` is the standard way to access the global object in any JavaScript environment — browsers, Node.js, and jsdom alike. You'll see it used in `setupTests.ts` for the `atob`/`btoa` polyfills.

---

## Submission

1. Complete all parts of the lab
2. Complete all TODO implementations and tests
3. Ensure all tests pass: `npm test`
4. Verify coverage: `npm run test:coverage`
5. Update your README with reflection and key concepts
6. Push your work:
   ```bash
   git add .
   git commit -m "Complete Lab 6: Login Flow"
   git push
   ```
7. Submit your repository URL on Canvas

**Due:** Monday, February 23, 2026 at 11:59 PM

⚠️ **Your repository stops accepting commits at the deadline.** Push early and often!
