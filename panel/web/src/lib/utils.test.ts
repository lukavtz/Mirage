import { describe, it, expect } from 'vitest'
import { cn } from './utils'

describe('cn', () => {
  it('joins class names and drops falsy values', () => {
    expect(cn('a', 'b', null, undefined, false, 0, '')).toBe('a b')
  })

  it('resolves tailwind-merge conflicts with the later class winning', () => {
    expect(cn('px-2', 'px-4')).toBe('px-4')
  })

  it('returns an empty string for no inputs', () => {
    expect(cn()).toBe('')
  })
})
