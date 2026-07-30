import { ShieldAlert } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'

export default function RefundPolicy() {
  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-3xl mx-auto p-6 space-y-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="rounded-lg bg-primary/10 p-2">
            <ShieldAlert className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">Refund Policy</h1>
            <p className="text-xs text-muted-foreground">Last updated: July 2026</p>
          </div>
        </div>

        <Card>
          <CardContent className="pt-6 space-y-4">
            <section>
              <h2 className="text-sm font-semibold mb-2">Monthly Subscriptions</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                You may request a full refund within 14 days of purchase for monthly subscription plans
                (Starter, Pro, Team monthly). Refunds are processed within 5–7 business days and will
                be returned to the original payment method.
              </p>
            </section>

            <section>
              <h2 className="text-sm font-semibold mb-2">Lifetime Licenses</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Lifetime license purchases are final and non-refundable. Due to the one-time nature
                of lifetime access, we cannot offer refunds or chargebacks on these purchases.
              </p>
            </section>

            <section>
              <h2 className="text-sm font-semibold mb-2">How to Request a Refund</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Contact support at <strong>support@mirage.local</strong> with your license key and
                purchase details. Refund requests for monthly subscriptions must be submitted within
                14 days of the original purchase date.
              </p>
            </section>

            <section>
              <h2 className="text-sm font-semibold mb-2">Exceptions</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Refunds may be denied if the license has been activated, the hardware ID (HWID) has
                been bound, or if abuse of the refund policy is detected. We reserve the right to
                refuse refunds at our discretion.
              </p>
            </section>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
