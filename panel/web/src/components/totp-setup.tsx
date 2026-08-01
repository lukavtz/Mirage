import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Loader2, ShieldCheck, ShieldOff } from 'lucide-react'

export function TotpSetupCard() {
  const queryClient = useQueryClient()

  const totpStatusQuery = useQuery({
    queryKey: ['totp-status'],
    queryFn: () => api.get<{ totp_enabled: boolean }>('/api/auth/me'),
    staleTime: 30000,
  })
  const totpEnabled = totpStatusQuery.data?.totp_enabled ?? false

  const [qrCode, setQrCode] = useState('')
  const [totpSecret, setTotpSecret] = useState('')
  const [verifyPasscode, setVerifyPasscode] = useState('')
  const [showTotpSetup, setShowTotpSetup] = useState(false)

  const totpSetupMutation = useMutation({
    mutationFn: () => api.post<{ secret: string; qr_base64: string }>('/api/auth/2fa/setup'),
    onSuccess: (data) => {
      setTotpSecret(data.secret)
      setQrCode(data.qr_base64)
      setShowTotpSetup(true)
    },
  })

  const totpVerifyMutation = useMutation({
    mutationFn: () => api.post('/api/auth/2fa/verify', { passcode: verifyPasscode }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['totp-status'] })
      setShowTotpSetup(false)
      setQrCode('')
      setTotpSecret('')
      setVerifyPasscode('')
    },
  })

  const totpDisableMutation = useMutation({
    mutationFn: () => api.post('/api/auth/2fa/disable'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['totp-status'] })
    },
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5" />
          Two-Factor Authentication
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {totpEnabled ? (
          <>
            <div className="flex items-center gap-2 text-sm text-success">
              <ShieldCheck className="h-4 w-4" />
              <span>2FA is enabled</span>
            </div>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => totpDisableMutation.mutate()}
              disabled={totpDisableMutation.isPending}
            >
              {totpDisableMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              <ShieldOff className="h-4 w-4 mr-2" />
              Disable 2FA
            </Button>
            {totpDisableMutation.isSuccess && <p className="text-sm text-success">2FA disabled</p>}
            {totpDisableMutation.isError && <p className="text-sm text-destructive">Failed to disable 2FA</p>}
          </>
        ) : showTotpSetup && qrCode ? (
          <>
            <p className="text-sm text-muted-foreground">
              Scan this QR code with your authenticator app, then enter the 6-digit code below.
            </p>
            <div className="flex justify-center py-2">
              <img
                src={`data:image/png;base64,${qrCode}`}
                alt="TOTP QR Code"
                className="rounded-lg border border-border"
                width={180}
                height={180}
              />
            </div>
            {totpSecret && (
              <div className="text-center">
                <p className="text-xs text-muted-foreground mb-1">Or enter this secret manually:</p>
                <code className="text-xs bg-muted px-2 py-1 rounded font-mono select-all">{totpSecret}</code>
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="totp-verify">Verification Code</Label>
              <Input
                id="totp-verify"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                maxLength={6}
                value={verifyPasscode}
                onChange={(e) => setVerifyPasscode(e.target.value.replace(/\D/g, ''))}
                className="text-center text-lg tracking-[0.5em] font-mono"
              />
            </div>
            <div className="flex gap-2">
              <Button
                onClick={() => totpVerifyMutation.mutate()}
                disabled={totpVerifyMutation.isPending || verifyPasscode.length < 6}
              >
                {totpVerifyMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                Enable 2FA
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  setShowTotpSetup(false)
                  setQrCode('')
                  setVerifyPasscode('')
                }}
              >
                Cancel
              </Button>
            </div>
            {totpVerifyMutation.isSuccess && <p className="text-sm text-success">2FA enabled!</p>}
            {totpVerifyMutation.isError && <p className="text-sm text-destructive">Invalid code, try again</p>}
          </>
        ) : (
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">
              Protect your account with a TOTP authenticator app (Google Authenticator, Authy, etc).
            </p>
            <Button
              onClick={() => totpSetupMutation.mutate()}
              disabled={totpSetupMutation.isPending}
            >
              {totpSetupMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              <ShieldCheck className="h-4 w-4 mr-2" />
              Set up 2FA
            </Button>
            {totpSetupMutation.isError && <p className="text-sm text-destructive">Failed to initialize 2FA setup</p>}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
