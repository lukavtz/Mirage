import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/hooks/use-auth'
import { Loader2, AlertCircle, Terminal, ShieldCheck } from 'lucide-react'

export default function Login() {
  const navigate = useNavigate()
  const { login, verifyTotp, totpRequired } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [passcode, setPasscode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const result = await login(username, password)
      if ('totp_required' in result) {
        setPasscode('')
      } else {
        navigate('/', { replace: true })
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  async function handleTotpSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await verifyTotp(passcode)
      navigate('/', { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed')
      setPasscode('')
    } finally {
      setLoading(false)
    }
  }

  if (totpRequired) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background relative before:fixed before:inset-0 before:-z-10 before:bg-[radial-gradient(1200px_600px_at_50%_-100px,hsl(262_64%_53%/0.18),transparent)] before:pointer-events-none">
        <Card className="w-full max-w-sm mx-4 shadow-card-lg border-border/80">
          <CardHeader className="text-center space-y-2">
            <div className="flex justify-center mb-2">
              <div className="relative rounded-lg bg-gradient-to-br from-brand-500 to-brand-700 p-2 shadow-glow">
                <ShieldCheck className="h-6 w-6 text-white" />
              </div>
            </div>
            <CardTitle className="text-xl">Two-Factor Authentication</CardTitle>
            <CardDescription>Enter the 6-digit code from your authenticator app</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleTotpSubmit} className="space-y-4">
              {error && (
                <div className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}
              <div className="space-y-2">
                <Label htmlFor="passcode">Passcode</Label>
                <Input
                  id="passcode"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="000000"
                  maxLength={6}
                  value={passcode}
                  onChange={(e) => setPasscode(e.target.value.replace(/\D/g, ''))}
                  required
                  autoFocus
                  className="text-center text-lg tracking-[0.5em] font-mono"
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading || passcode.length < 6}>
                {loading && <Loader2 className="h-4 w-4 animate-spin" />}
                {loading ? 'Verifying...' : 'Verify'}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background relative before:fixed before:inset-0 before:-z-10 before:bg-[radial-gradient(1200px_600px_at_50%_-100px,hsl(262_64%_53%/0.18),transparent)] before:pointer-events-none">
      <Card className="w-full max-w-sm mx-4 shadow-card-lg border-border/80">
        <CardHeader className="text-center space-y-2">
          <div className="flex justify-center mb-2">
            <div className="relative rounded-lg bg-gradient-to-br from-brand-500 to-brand-700 p-2 shadow-glow">
              <Terminal className="h-6 w-6 text-white" />
            </div>
          </div>
          <CardTitle className="text-xl">Eidos Panel</CardTitle>
          <CardDescription>Sign in to your command center</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                type="text"
                placeholder="admin"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
