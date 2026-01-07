import { describe, expect, it, beforeEach } from 'vitest'
import { OIDCService } from './oidc'

function setTokensRaw(raw: string) {
  localStorage.setItem('oidc_tokens', raw)
}

function setTokens(tokens: any) {
  localStorage.setItem('oidc_tokens', JSON.stringify(tokens))
}

describe('OIDCService token handling', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('returns null for invalid stored JSON', () => {
    const svc = new OIDCService()
    setTokensRaw('{not-json')

    expect(svc.getStoredTokens()).toBeNull()
  })

  it('clears unusable tokens when idToken is invalid', () => {
    const svc = new OIDCService()

    setTokens({
      accessToken: 'a',
      refreshToken: 'r',
      idToken: 'not-a-jwt',
      expiresAt: Date.now() + 60_000,
    })

    expect(svc.getCurrentUser()).toBeNull()
    expect(localStorage.getItem('oidc_tokens')).toBeNull()
  })
})
