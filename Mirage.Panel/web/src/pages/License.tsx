import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { KeyRound, CheckCircle2, XCircle, Loader2 } from 'lucide-react'

interface LicenseInfo {
    tier: string
    expires_at: string
    days_left: number
}

interface ActivateResponse {
    tier: string
    valid_until: string
}

export default function LicensePage() {
    const [key, setKey] = useState('')
    const [success, setSuccess] = useState('')
    const [error, setError] = useState('')

    const licenseQuery = useQuery({
        queryKey: ['license'],
        queryFn: () => api.get<LicenseInfo>('/api/license'),
    })

    const activateMutation = useMutation({
        mutationFn: () => api.post<ActivateResponse>('/api/license/activate', { key }),
        onSuccess: (data) => {
            setSuccess(`License activated: ${data.tier} tier, valid until ${data.valid_until}`)
            setError('')
            setKey('')
            licenseQuery.refetch()
        },
        onError: (err: any) => {
            setError(err?.error || 'Failed to activate license')
            setSuccess('')
        },
    })

    return (
        <div className="space-y-6">
            <h1 className="text-2xl font-bold flex items-center gap-2"><KeyRound className="h-5 w-5" />License</h1>

            <Card>
                <CardHeader><CardTitle className="text-sm font-medium">Current License</CardTitle></CardHeader>
                <CardContent>
                    {licenseQuery.isLoading ? (
                        <div className="flex items-center gap-2 text-muted-foreground">
                            <Loader2 className="h-4 w-4 animate-spin" />
                            Loading...
                        </div>
                    ) : licenseQuery.data ? (
                        <div className="flex items-center gap-3">
                            <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                            <div className="text-sm">
                                <span className="font-medium capitalize">{licenseQuery.data.tier}</span>
                                <span className="text-muted-foreground"> tier, expires in {licenseQuery.data.days_left} days</span>
                            </div>
                        </div>
                    ) : (
                        <div className="flex items-center gap-3">
                            <XCircle className="h-5 w-5 text-destructive" />
                            <span className="text-sm text-muted-foreground">No active license</span>
                        </div>
                    )}
                </CardContent>
            </Card>

            <Card>
                <CardHeader><CardTitle className="text-sm font-medium">Activate License</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                    <div className="space-y-2">
                        <Label htmlFor="license-key">License Key</Label>
                        <div className="flex gap-2">
                            <Input
                                id="license-key"
                                placeholder="Enter your license key"
                                value={key}
                                onChange={e => setKey(e.target.value)}
                                className="font-mono flex-1"
                            />
                            <Button
                                onClick={() => activateMutation.mutate()}
                                disabled={!key.trim() || activateMutation.isPending}
                            >
                                {activateMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                                Activate
                            </Button>
                        </div>
                    </div>
                    {success && (
                        <div className="flex items-center gap-2 rounded-md bg-emerald-500/10 p-3 text-sm text-emerald-600 dark:text-emerald-400">
                            <CheckCircle2 className="h-4 w-4 shrink-0" />
                            {success}
                        </div>
                    )}
                    {error && (
                        <div className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive">
                            <XCircle className="h-4 w-4 shrink-0" />
                            {error}
                        </div>
                    )}
                </CardContent>
            </Card>
        </div>
    )
}
