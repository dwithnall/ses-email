import Layout from "../components/Layout";
import PageHeader from "../components/PageHeader";

export default function AfterHours() {
  return (
    <Layout>
      <PageHeader title="When We're Closed" />
      <div className="mx-auto max-w-3xl space-y-10 px-4 py-12">
        <section className="rounded-lg border border-red-200 bg-red-50 p-6">
          <h2 className="text-lg font-bold text-red-800">Life-threatening emergencies</h2>
          <p className="mt-2 text-sm text-red-900">
            Call <strong>000</strong> immediately. Do not wait or drive yourself.
          </p>
          <ul className="mt-3 space-y-1 text-sm text-red-900">
            <li>Mount Barker Hospital, Wellington Road, Mount Barker &mdash; (08) 8393 1777</li>
            <li>Modbury Hospital, Smart Road, Modbury &mdash; (08) 8161 2000</li>
          </ul>
        </section>

        <section>
          <h2 className="text-lg font-bold text-brand-900">Urgent care (non-emergency)</h2>
          <div className="mt-4 space-y-4 text-sm text-slate-700">
            <div>
              <p className="font-semibold text-brand-800">Gumeracha Nurse-Led Clinic</p>
              <p className="mt-1">
                Nurses see patients aged 5 and over, with a doctor available by video
                when needed. Treats coughs, infections, gastro, UTIs, cuts, sprains,
                burns, rashes, bites, stings, wound dressings, and sick certificates.
                Free with a Medicare card.
              </p>
              <p className="mt-1">
                Gumeracha District Soldiers&rsquo; Memorial Hospital, 2 Albert Street.
                1pm&ndash;8pm weekdays; 9am&ndash;4pm weekends/public holidays. Phone (08) 8209 9220.
              </p>
            </div>
            <div>
              <p className="font-semibold text-brand-800">Medicare Urgent Care Clinics</p>
              <p className="mt-1">Walk-in, bulk-billed clinics in Adelaide:</p>
              <ul className="mt-1 list-disc space-y-1 pl-5">
                <li>Norwood: 201&ndash;203 The Parade (7:30am&ndash;9:30pm daily)</li>
                <li>Para Hills West: 33 McIntyre Road (8am&ndash;8pm weekdays; 10am&ndash;6pm weekends/holidays)</li>
              </ul>
            </div>
          </div>
        </section>

        <section>
          <h2 className="text-lg font-bold text-brand-900">Home visits</h2>
          <p className="mt-2 text-sm text-slate-700">
            Hello Home Doctor: call 134 100. Weeknights from 6pm; Saturday midday
            through the weekend; all day on public holidays. Bulk bills eligible
            patients.
          </p>
        </section>

        <section>
          <h2 className="text-lg font-bold text-brand-900">24/7 telehealth &amp; advice</h2>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-700">
            <li>1800MEDICARE: 1800 633 422 (free nurse line; GP video consult available after hours)</li>
            <li>Healthdirect: 1800 022 222 (free 24-hour nurse line)</li>
          </ul>
        </section>

        <section>
          <h2 className="text-lg font-bold text-brand-900">Children&rsquo;s virtual urgent care</h2>
          <p className="mt-2 text-sm text-slate-700">
            Ages 6 months&ndash;18 years. Women&rsquo;s and Children&rsquo;s Hospital virtual urgent
            care, 9am&ndash;9pm daily: wch.sa.gov.au/virtualurgentcare
          </p>
        </section>

        <section>
          <h2 className="text-lg font-bold text-brand-900">Mental health crisis</h2>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-700">
            <li>SA Mental Health Triage: 13 14 65 (any hour)</li>
            <li>Lifeline: 13 11 14</li>
          </ul>
        </section>
      </div>
    </Layout>
  );
}
