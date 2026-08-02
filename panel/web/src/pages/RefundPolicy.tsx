import { ShieldAlert } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { useI18n } from '@/lib/i18n'

export default function RefundPolicy() {
  const { t } = useI18n()
  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-3xl mx-auto p-6 space-y-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="rounded-lg bg-primary/10 p-2">
            <ShieldAlert className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">{t('refund.title')}</h1>
            <p className="text-xs text-muted-foreground">{t('refund.updated')}</p>
          </div>
        </div>

        <Card>
          <CardContent className="pt-6 space-y-4">
            <section>
              <h2 className="text-sm font-semibold mb-2">{t('refund.monthly_title')}</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {t('refund.monthly_text')} Refunds are processed within 5–7 business days and will
                be returned to the original payment method.
              </p>
            </section>

            <section>
              <h2 className="text-sm font-semibold mb-2">{t('refund.lifetime_title')}</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {t('refund.lifetime_text')} Due to the one-time nature
                of lifetime access, we cannot offer refunds or chargebacks on these purchases.
              </p>
            </section>

            <section>
              <h2 className="text-sm font-semibold mb-2">{t('refund.how_to_title')}</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {t('refund.how_to_text')} Refund requests for monthly subscriptions must be submitted within
                14 days of the original purchase date.
              </p>
            </section>

            <section>
              <h2 className="text-sm font-semibold mb-2">{t('refund.exceptions_title')}</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {t('refund.exceptions_text')} We reserve the right to
                refuse refunds at our discretion.
              </p>
            </section>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
