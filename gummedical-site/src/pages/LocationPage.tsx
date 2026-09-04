import Layout from "../components/Layout";
import PageHeader from "../components/PageHeader";
import { locations } from "../data/locations";
import NotFound from "./NotFound";

export default function LocationPage({ slug }: { slug: "gumeracha" | "lobethal" }) {
  const location = locations.find((l) => l.slug === slug);

  if (!location) return <NotFound />;

  return (
    <Layout>
      <PageHeader title={`Gum Medical ${location.name}`} subtitle={location.address} />
      <div className="mx-auto grid max-w-6xl gap-12 px-4 py-12 lg:grid-cols-2">
        <div>
          <h2 className="text-xl font-bold text-brand-900">Contact</h2>
          <dl className="mt-4 space-y-2 text-sm text-slate-700">
            <div className="flex gap-2"><dt className="font-medium">Address:</dt><dd>{location.address}</dd></div>
            <div className="flex gap-2"><dt className="font-medium">Phone:</dt><dd>{location.phone}</dd></div>
            <div className="flex gap-2"><dt className="font-medium">Fax:</dt><dd>{location.fax}</dd></div>
            <div className="flex gap-2"><dt className="font-medium">Email:</dt><dd>{location.email} (administrative enquiries only)</dd></div>
          </dl>

          <h2 className="mt-8 text-xl font-bold text-brand-900">Hours</h2>
          <ul className="mt-4 list-disc space-y-1 pl-5 text-sm text-slate-700">
            {location.hours.map((h) => (
              <li key={h}>{h}</li>
            ))}
          </ul>

          <a
            href={location.hotdocUrl}
            target="_blank"
            rel="noreferrer"
            className="mt-6 inline-block rounded-md bg-brand-600 px-5 py-2.5 font-semibold text-white hover:bg-brand-700"
          >
            Book online with HotDoc
          </a>
        </div>

        <div>
          <h2 className="text-xl font-bold text-brand-900">About this practice</h2>
          <p className="mt-4 text-sm text-slate-700">{location.history}</p>

          <h2 className="mt-8 text-xl font-bold text-brand-900">Pathology</h2>
          <p className="mt-4 text-sm text-slate-700">{location.pathology}</p>

          <h2 className="mt-8 text-xl font-bold text-brand-900">Access &amp; parking</h2>
          <p className="mt-4 text-sm text-slate-700">{location.description}</p>
        </div>
      </div>
    </Layout>
  );
}
