import { useState, useRef, useCallback, type FormEvent, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { useTheme } from '@/lib/theme-provider'
import { useI18n } from '@/lib/i18n'
import { Eye, EyeOff, Sun, Moon, ArrowRight } from 'lucide-react'
import { motion, AnimatePresence, useReducedMotion } from 'motion/react'


// ── 6-digit OTP input ───────────────────────────────────────────────
function OtpInput({ value, onChange, error }: {
  value: string
  onChange: (v: string) => void
  error: boolean
}) {
  const refs = useRef<(HTMLInputElement | null)[]>([])

  const focus = (i: number) => {
    refs.current[i]?.focus()
    refs.current[i]?.select()
  }

  const handleChange = (i: number, v: string) => {
    const digit = v.replace(/\D/g, '').slice(-1)
    const next = value.split('')
    next[i] = digit
    const joined = next.join('').padEnd(6, '').slice(0, 6)
    onChange(joined)
    if (digit && i < 5) focus(i + 1)
  }

  const handleKeyDown = (i: number, e: ReactKeyboardEvent) => {
    if (e.key === 'Backspace' && !value[i] && i > 0) {
      focus(i - 1)
    }
  }

  const handlePaste = (e: React.ClipboardEvent) => {
    e.preventDefault()
    const digits = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    onChange(digits.padEnd(6, '').slice(0, 6))
    if (digits.length > 0) focus(Math.min(digits.length, 5))
  }

  return (
    <div className="flex justify-center gap-3">
      {Array.from({ length: 6 }).map((_, i) => (
        <input
          key={i}
          ref={el => { refs.current[i] = el }}
          type="text"
          inputMode="numeric"
          maxLength={1}
          autoComplete="one-time-code"
          value={value[i] ?? ''}
          onChange={e => handleChange(i, e.target.value)}
          onKeyDown={e => handleKeyDown(i, e)}
          onPaste={handlePaste}
          onFocus={e => e.target.select()}
          className={`
            w-12 h-14 text-center text-xl font-mono font-medium
            bg-transparent outline-none transition-all duration-200
            border-b-2 ${error ? 'border-red-400' : value[i] ? 'border-foreground' : 'border-border'}
            focus:border-foreground
            text-foreground
          `}
        />
      ))}
    </div>
  )
}


// ── Main Login component ────────────────────────────────────────────
export default function Login() {
  const navigate = useNavigate()
  const { login, verifyTotp, totpRequired } = useAuth()
  const { t, lang, setLang } = useI18n()
  const { theme, setTheme } = useTheme()
  const shouldReduceMotion = useReducedMotion()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [rememberMe, setRememberMe] = useState(true)
  const [passcode, setPasscode] = useState('')
  const [fieldErrors, setFieldErrors] = useState<{ username?: string; password?: string }>({})
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [fadeOut, setFadeOut] = useState(false)
  const [forgotView, setForgotView] = useState(false)
  const [forgotStep, setForgotStep] = useState<'request' | 'reset'>('request')
  const [resetToken, setResetToken] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [forgotMessage, setForgotMessage] = useState('')
  const handleSuccess = useCallback(() => {
    setFadeOut(true)
    setTimeout(() => navigate('/', { replace: true }), 400)
  }, [navigate])

  const handleSubmit = useCallback(async (e: FormEvent) => {
    e.preventDefault()
    const nextErrors = {
      username: username.trim() ? undefined : t('auth.username_required'),
      password: password ? undefined : t('auth.password_required'),
    }
    setFieldErrors(nextErrors)
    if (nextErrors.username || nextErrors.password) return

    setError('')
    setLoading(true)
    try {
      const result = await login(username, password, rememberMe)
      if ('totp_required' in result) {
        setPasscode('')
      } else {
        handleSuccess()
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : t('auth.login_failed'))
    } finally {
      setLoading(false)
    }
  }, [login, username, password, rememberMe, t, handleSuccess])

  const handleTotpSubmit = useCallback(async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await verifyTotp(passcode)
      handleSuccess()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('auth.verify_failed'))
      setPasscode('')
    } finally {
      setLoading(false)
    }
  }, [verifyTotp, passcode, t, handleSuccess])

  const handleForgotRequest = useCallback(async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      })
      const data = await res.json()
      if (res.ok && data.token) {
        setResetToken(data.token)
        setForgotStep('reset')
        setForgotMessage('')
      } else {
        setForgotMessage(data.error || t('auth.forgot_error'))
      }
    } catch {
      setForgotMessage(t('auth.forgot_error'))
    } finally {
      setLoading(false)
    }
  }, [username, t])

  const handleResetPassword = useCallback(async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: resetToken, new_password: newPassword }),
      })
      const data = await res.json()
      if (res.ok) {
        setForgotView(false)
        setForgotStep('request')
        setResetToken('')
        setNewPassword('')
        setError('')
        setForgotMessage(t('auth.reset_success'))
      } else {
        setError(data.error || t('auth.reset_error'))
      }
    } catch {
      setError(t('auth.reset_error'))
    } finally {
      setLoading(false)
    }
  }, [resetToken, newPassword, t])

  const toggleLang = () => setLang(lang === 'en' ? 'ru' : 'en')

  const selectTheme = (nextTheme: 'light' | 'dark', target: HTMLButtonElement) => {
    if (nextTheme === theme) return

    const rect = target.getBoundingClientRect()
    const root = document.documentElement
    root.style.setProperty('--theme-reveal-x', `${rect.left + rect.width / 2}px`)
    root.style.setProperty('--theme-reveal-y', `${rect.top + rect.height / 2}px`)
    const documentWithViewTransition = document as Document & { startViewTransition?: (update: () => void) => void }

    if (documentWithViewTransition.startViewTransition && !shouldReduceMotion) {
      documentWithViewTransition.startViewTransition(() => setTheme(nextTheme))
      return
    }

    setTheme(nextTheme)
  }

  return (
    <motion.div
      initial={{ opacity: 1 }}
      animate={{ opacity: fadeOut ? 0 : 1 }}
      transition={{ duration: 0.4, ease: [0.2, 0.8, 0.2, 1] }}
      className="flex min-h-screen p-2"
      style={{ backgroundColor: theme === 'dark' ? '#0A0A0A' : '#ECECEC' }}
    >
      {/* ── Left Panel: Brand ──────────────────────────────────── */}
      <div className="hidden lg:flex lg:w-[42%] relative flex-col justify-between p-10 overflow-hidden rounded-l-2xl">
        <img
          src={theme === 'dark' ? '/auth-dark.webp' : '/auth-light.webp'}
          alt=""
          aria-hidden="true"
          className="absolute inset-0 size-full object-cover"
        />
        <div className={`absolute inset-0 ${theme === 'dark' ? 'bg-black/15' : 'bg-white/35'}`} />

        <div className="relative z-10 flex-1 flex flex-col items-center justify-center">
          <h1
            className="pl-[0.42em] text-[28px] font-medium tracking-[0.42em] select-none"
            style={{
              fontFamily: 'var(--font-sans)',
              color: theme === 'dark' ? '#F5F5F5' : '#111111',
            }}
          >
            MIRAGE
          </h1>
          <p
            className="mt-3 pl-[0.52em] text-[9px] font-medium tracking-[0.52em] uppercase select-none"
            style={{ color: theme === 'dark' ? '#B0B0B0' : '#555555' }}
          >
            SOFTWARE. ELEVATED.
          </p>
        </div>

        <p
          className="relative z-10 text-[11px] select-none"
          style={{ color: theme === 'dark' ? '#B0B0B0' : '#555555' }}
        >
          &copy; 2026 Mirage. All rights reserved.
        </p>
      </div>

      {/* ── Right Panel: Auth ──────────────────────────────────── */}
      <div
        className="flex-1 flex flex-col relative overflow-hidden rounded-2xl lg:rounded-l-none lg:rounded-r-2xl"
        style={{ backgroundColor: theme === 'dark' ? '#141414' : '#FFFFFF' }}
      >
        {/* Top-right controls */}
        <div className="flex items-center justify-end gap-3 p-6">
          <button
            onClick={toggleLang}
            className="text-[11px] font-medium tracking-wide uppercase px-2 py-1 rounded transition-colors duration-200 hover:opacity-70"
            style={{ color: theme === 'dark' ? '#B0B0B0' : '#555555' }}
          >
            {lang === 'en' ? 'RU' : 'EN'}
          </button>
          <div
            className="relative flex items-center rounded-full border border-border bg-muted/70 p-1"
            role="group"
            aria-label="Theme"
          >
            {(['light', 'dark'] as const).map(value => {
              const active = theme === value
              const Icon = value === 'light' ? Sun : Moon
              return (
                <motion.button
                  key={value}
                  type="button"
                  onClick={event => selectTheme(value, event.currentTarget)}
                  aria-label={`Use ${value} theme`}
                  aria-pressed={active}
                  title={`Use ${value} theme`}
                  whileHover={{ scale: 1.08 }}
                  whileTap={{ scale: 0.9 }}
                  transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                  className={`relative z-10 size-9 rounded-full flex items-center justify-center ${active ? 'text-foreground' : 'text-muted-foreground hover:text-foreground'}`}
                >
                  {active && (
                    <motion.span
                      layoutId="active-theme"
                      className="absolute inset-0 -z-10 rounded-full bg-background shadow-sm"
                      transition={{ type: 'spring', stiffness: 500, damping: 35 }}
                    />
                  )}
                  <Icon className="size-4" />
                </motion.button>
              )
            })}
          </div>
        </div>

        {/* Form area */}
        <div className="flex-1 flex items-center justify-center px-6 pb-20">
          <div className="w-full max-w-[444px]">
            <AnimatePresence mode="wait">
              {forgotView ? (
                <motion.div
                  key="forgot"
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.25, ease: [0.2, 0.8, 0.2, 1] }}
                >
                  <button type="button" onClick={() => { setForgotView(false); setError(''); setForgotStep('request'); setForgotMessage('') }} className="text-[12px] mb-6 text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
                    ← {t('auth.back_to_login')}
                  </button>
                  <h2 className="text-[28px] font-semibold tracking-tight mb-2 text-foreground">
                    {forgotStep === 'request' ? t('auth.forgot_title') : t('auth.reset_title')}
                  </h2>
                  <p className="text-sm mb-10 text-muted-foreground">
                    {forgotStep === 'request' ? t('auth.forgot_desc') : t('auth.reset_desc')}
                  </p>
                  {forgotStep === 'request' ? (
                    <form onSubmit={handleForgotRequest} className="space-y-6">
                      <div className="space-y-2">
                        <label htmlFor="forgot-username" className="block text-[11px] font-medium tracking-[0.12em] uppercase text-muted-foreground">{t('auth.username')}</label>
                        <input id="forgot-username" type="text" value={username} onChange={e => setUsername(e.target.value)} required autoFocus className="h-11 w-full border-0 border-b border-border bg-transparent px-0 text-[16px] text-foreground outline-none transition-colors duration-200 focus:border-foreground" />
                      </div>
                      {forgotMessage && <p className="text-[12px] text-status-online">{forgotMessage}</p>}
                      {error && <p className="text-[12px] text-status-error">{error}</p>}
                      <button type="submit" disabled={loading || !username} className="w-full h-[54px] rounded-[10px] flex items-center justify-center gap-2 text-[15px] font-medium transition-all duration-200 disabled:opacity-40 bg-foreground text-background">
                        {loading ? <span className="flex gap-1"><span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" /><span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" style={{ animationDelay: '150ms' }} /><span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" style={{ animationDelay: '300ms' }} /></span> : <>{t('auth.forgot_submit')}<ArrowRight className="size-4" /></>}
                      </button>
                    </form>
                  ) : (
                    <form onSubmit={handleResetPassword} className="space-y-6">
                      <div className="space-y-2">
                        <label htmlFor="reset-code" className="block text-[11px] font-medium tracking-[0.12em] uppercase text-muted-foreground">{t('auth.reset_code')}</label>
                        <input id="reset-code" type="text" value={resetToken} onChange={e => setResetToken(e.target.value)} required autoFocus className="h-11 w-full border-0 border-b border-border bg-transparent px-0 text-[14px] font-mono text-foreground outline-none transition-colors duration-200 focus:border-foreground" placeholder="Enter the code you received" />
                      </div>
                      <div className="space-y-2">
                        <label htmlFor="new-password" className="block text-[11px] font-medium tracking-[0.12em] uppercase text-muted-foreground">{t('auth.new_password')}</label>
                        <input id="new-password" type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} required minLength={8} className="h-11 w-full border-0 border-b border-border bg-transparent px-0 text-[16px] text-foreground outline-none transition-colors duration-200 focus:border-foreground" />
                      </div>
                      {error && <p className="text-[12px] text-status-error">{error}</p>}
                      {forgotMessage && <p className="text-[12px] text-status-online">{forgotMessage}</p>}
                      <button type="submit" disabled={loading || newPassword.length < 8} className="w-full h-[54px] rounded-[10px] flex items-center justify-center gap-2 text-[15px] font-medium transition-all duration-200 disabled:opacity-40 bg-foreground text-background">
                        {loading ? <span className="flex gap-1"><span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" /><span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" style={{ animationDelay: '150ms' }} /><span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" style={{ animationDelay: '300ms' }} /></span> : <>{t('auth.reset_submit')}<ArrowRight className="size-4" /></>}
                      </button>
                    </form>
                  )}
                </motion.div>
              ) : totpRequired ? (
                <motion.div
                  key="totp"
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.25, ease: [0.2, 0.8, 0.2, 1] }}
                >
                  <h2 className="text-[28px] font-semibold tracking-tight mb-2 text-foreground" style={{ fontFamily: 'var(--font-display, var(--font-sans))' }}>
                    {t('auth.totp_title')}
                  </h2>
                  <p className="text-sm mb-10 text-muted-foreground">{t('auth.totp_subtitle')}</p>
                  <form onSubmit={handleTotpSubmit}>
                    <OtpInput value={passcode} onChange={setPasscode} error={!!error} />
                    {error && <p className="text-[12px] text-status-error mt-4 text-center">{error}</p>}
                    <button type="submit" disabled={loading || passcode.length < 6} className="w-full h-[54px] mt-8 rounded-[10px] flex items-center justify-center gap-2 text-[15px] font-medium transition-all duration-200 disabled:opacity-40 bg-foreground text-background">
                      {loading ? <span className="flex gap-1"><span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" /><span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" style={{ animationDelay: '150ms' }} /><span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" style={{ animationDelay: '300ms' }} /></span> : <>{t('auth.verify')}<ArrowRight className="size-4" /></>}
                    </button>
                  </form>
                </motion.div>
              ) : (
                <motion.div
                  key="login"
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.25, ease: [0.2, 0.8, 0.2, 1] }}
                >
                  {/* Login Form */}
                  <h2
                    className="text-[28px] font-semibold tracking-tight mb-2"
                    style={{
                      fontFamily: 'var(--font-display, var(--font-sans))',
                      color: theme === 'dark' ? '#F5F5F5' : '#111111',
                    }}
                  >
                    {t('auth.welcome')}
                  </h2>
                  <p
                    className="text-sm mb-14"
                    style={{ color: theme === 'dark' ? '#B0B0B0' : '#555555' }}
                  >
                    {t('auth.signin_desc')}
                  </p>

                  <form onSubmit={handleSubmit} noValidate className="space-y-5">
                    <div className="space-y-2">
                      <label
                        htmlFor="username"
                        className="block text-[11px] font-medium tracking-[0.12em] uppercase"
                        style={{ color: theme === 'dark' ? '#B0B0B0' : '#555555' }}
                      >
                        {t('auth.username')}
                      </label>
                      <input
                        id="username"
                        type="text"
                        value={username}
                        onChange={event => {
                          setUsername(event.target.value)
                          if (fieldErrors.username) setFieldErrors(current => ({ ...current, username: undefined }))
                        }}
                        autoFocus
                        autoComplete="username"
                        aria-invalid={!!fieldErrors.username}
                        aria-describedby={fieldErrors.username ? 'username-error' : undefined}
                        className="h-11 w-full border-0 border-b bg-transparent px-0 text-[16px] text-foreground outline-none transition-colors duration-200 placeholder:text-muted-foreground/40 focus:border-foreground aria-[invalid=true]:border-destructive"
                      />
                      <AnimatePresence initial={false}>
                        {fieldErrors.username && (
                          <motion.p
                            id="username-error"
                            role="alert"
                            initial={{ opacity: 0, y: -4 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -4 }}
                            className="text-xs text-destructive"
                          >
                            {fieldErrors.username}
                          </motion.p>
                        )}
                      </AnimatePresence>
                    </div>

                    <div className="space-y-2">
                      <label
                        htmlFor="password"
                        className="block text-[11px] font-medium tracking-[0.12em] uppercase"
                        style={{ color: theme === 'dark' ? '#B0B0B0' : '#555555' }}
                      >
                        {t('auth.password')}
                      </label>
                      <div className="relative">
                        <input
                          id="password"
                          type={showPassword ? 'text' : 'password'}
                          value={password}
                          onChange={event => {
                            setPassword(event.target.value)
                            if (fieldErrors.password) setFieldErrors(current => ({ ...current, password: undefined }))
                          }}
                          autoComplete="current-password"
                          aria-invalid={!!fieldErrors.password}
                          aria-describedby={fieldErrors.password ? 'password-error' : undefined}
                          className="h-11 w-full border-0 border-b bg-transparent px-0 pr-12 text-[16px] text-foreground outline-none transition-colors duration-200 placeholder:text-muted-foreground/40 focus:border-foreground aria-[invalid=true]:border-destructive"
                        />
                        <motion.button
                          type="button"
                          onClick={() => setShowPassword(value => !value)}
                          aria-label={showPassword ? 'Hide password' : 'Show password'}
                          whileHover={{ scale: 1.12 }}
                          whileTap={{ scale: 0.86, rotate: showPassword ? -12 : 12 }}
                          transition={{ type: 'spring', stiffness: 500, damping: 26 }}
                          className="absolute right-0 top-1/2 -translate-y-1/2 size-10 flex items-center justify-center text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                        >
                          <AnimatePresence mode="wait" initial={false}>
                            <motion.span
                              key={showPassword ? 'hidden' : 'visible'}
                              initial={{ opacity: 0, rotate: -45, scale: 0.7 }}
                              animate={{ opacity: 1, rotate: 0, scale: 1 }}
                              exit={{ opacity: 0, rotate: 45, scale: 0.7 }}
                              transition={{ duration: 0.16 }}
                            >
                              {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                            </motion.span>
                          </AnimatePresence>
                        </motion.button>
                      </div>
                      <AnimatePresence initial={false}>
                        {fieldErrors.password && (
                          <motion.p
                            id="password-error"
                            role="alert"
                            initial={{ opacity: 0, y: -4 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -4 }}
                            className="text-xs text-destructive"
                          >
                            {fieldErrors.password}
                          </motion.p>
                        )}
                      </AnimatePresence>
                    </div>

                    {/* Error */}
                    <AnimatePresence>
                      {error && (
                        <motion.p
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                          className="text-[12px] text-red-400 overflow-hidden"
                        >
                          {error}
                        </motion.p>
                      )}
                    </AnimatePresence>

                    {/* Remember me + Forgot password */}
                    <div className="flex items-center justify-between">
                      <label className="flex items-center gap-2.5 cursor-pointer select-none">
                        <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} className="size-3.5 accent-foreground" />
                        <span className="text-[12px] text-muted-foreground">{t('auth.remember_me')}</span>
                      </label>
                      <button type="button" onClick={() => { setForgotView(true); setError(''); setForgotMessage('') }} className="text-[12px] text-muted-foreground hover:text-foreground transition-colors">
                        {t('auth.forgot_password')}
                      </button>
                    </div>
                    <motion.button
                      type="submit"
                      disabled={loading}
                      whileHover={loading ? undefined : { y: -2, scale: 1.01 }}
                      whileTap={loading ? undefined : { scale: 0.985 }}
                      transition={{ type: 'spring', stiffness: 420, damping: 24 }}
                      className="group relative isolate h-14 w-full overflow-hidden rounded-xl bg-foreground text-background disabled:opacity-40"
                      style={{ boxShadow: theme === 'dark' ? '0 14px 32px rgba(255,255,255,0.1)' : '0 14px 32px rgba(0,0,0,0.16)' }}
                    >
                      <motion.span
                        aria-hidden="true"
                        className="absolute inset-y-0 -left-1/2 w-1/2 -skew-x-12 bg-linear-to-r from-transparent via-background/25 to-transparent"
                        initial={false}
                        animate={loading ? { x: '280%' } : { x: 0 }}
                        transition={{ duration: 0.8, ease: [0.2, 0.8, 0.2, 1] }}
                      />
                      <span className="relative flex h-full items-center justify-center gap-2 text-[15px] font-medium">
                        {loading ? (
                          <span className="flex gap-1">
                            <span className="size-1.5 rounded-full bg-current animate-pulse" style={{ animationDelay: '0ms' }} />
                            <span className="size-1.5 rounded-full bg-current animate-pulse" style={{ animationDelay: '150ms' }} />
                            <span className="size-1.5 rounded-full bg-current animate-pulse" style={{ animationDelay: '300ms' }} />
                          </span>
                        ) : (
                          <>
                            {t('auth.login')}
                            <motion.span whileHover={{ x: 3 }} transition={{ type: 'spring', stiffness: 500, damping: 25 }}>
                              <ArrowRight className="size-4" />
                            </motion.span>
                          </>
                        )}
                      </span>
                    </motion.button>
                  </form>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </motion.div>
  )
}
