import Layout from "../components/Layout";
import PageHeader from "../components/PageHeader";
import { locations } from "../data/locations";
import { feeSchedule } from "../data/services";

export default function AppointmentsAndFees() {
  return (
    <Layout>
      <PageHeader
        title="Appointments & Fees"
        subtitle="Longer appointments are necessary for some conditions: for example new patients, mental health issues, or multiple problems. Standard consultations typically allow 15 minutes."
      />

      <div className="mx-auto max-w-6xl px-4 py-12">
        <div className="grid gap-6 sm:grid-cols-2">
          {locations.map((loc) => (
            <div key={loc.slug} className="rounded-lg border border-brand-100 p-6">
              <h2 className="font-semibold text-brand-800">{loc.name}</h2>
              <p className="mt-1 text-sm text-slate-600">{loc.address}</p>
              <p className="text-sm text-slate-600">{loc.phone}</p>
              <a
                href={loc.hotdocUrl}
                target="_blank"
                rel="noreferrer"
                className="mt-3 inline-block rounded-md bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700"
              >
                Book online with HotDoc
              </a>
            </div>
          ))}
        </div>

        <h2 className="mt-12 text-2xl font-bold text-brand-900">Consultation fees</h2>
        <p className="mt-2 text-sm text-slate-600">
          This is a mixed-billing practice. Care Plans, Chronic Condition Management
          (CDM), and Health Assessments remain bulk billed. Standard consultations
          attract an out-of-pocket fee. Financial hardship cases receive discretionary
          consideration from doctors. Effective 1 November 2025.
        </p>

        <div className="mt-6 overflow-x-auto">
          <table className="w-full min-w-[560px] border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-brand-200 text-brand-800">
                <th className="py-2 pr-4">Consultation type</th>
                <th className="py-2 pr-4">Duration</th>
                <th className="py-2 pr-4">Total fee</th>
                <th className="py-2 pr-4">Medicare rebate</th>
                <th className="py-2">Out-of-pocket</th>
              </tr>
            </thead>
            <tbody>
              {feeSchedule.map((row) => (
                <tr key={row.type} className="border-b border-slate-100">
                  <td className="py-2 pr-4 font-medium text-slate-800">{row.type}</td>
                  <td className="py-2 pr-4 text-slate-600">{row.duration}</td>
                  <td className="py-2 pr-4 text-slate-600">{row.totalFee}</td>
                  <td className="py-2 pr-4 text-slate-600">{row.rebate}</td>
                  <td className="py-2 text-slate-600">{row.outOfPocket}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-xs text-slate-500">Procedures incur additional complexity-based fees.</p>

        <h2 className="mt-12 text-xl font-bold text-brand-900">Payment</h2>
        <p className="mt-2 text-sm text-slate-600">
          Payment is required on the day. Medicare rebates are processed
          electronically, with refunds typically appearing in your bank account
          within 24–48 hours.
        </p>

        <h2 className="mt-8 text-xl font-bold text-brand-900">Cancellations &amp; non-attendance</h2>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-600">
          <li>Non-attendance: full consultation fee charged.</li>
          <li>Late cancellation (within 2 business hours): gap payment amount charged.</li>
          <li>These fees are not claimable through Medicare and must be settled before rebooking.</li>
          <li>Repeated absences may result in restricted booking privileges.</li>
        </ul>
      </div>
    </Layout>
  );
}
