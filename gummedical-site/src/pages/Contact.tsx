import { Link } from "react-router-dom";
import Layout from "../components/Layout";
import PageHeader from "../components/PageHeader";
import ContactForm from "../components/ContactForm";
import { locations } from "../data/locations";

export default function Contact() {
  return (
    <Layout>
      <PageHeader title="Contact" subtitle="Get in touch with Gum Medical, Gumeracha or Lobethal." />
      <div className="mx-auto grid max-w-6xl gap-12 px-4 py-12 lg:grid-cols-2">
        <div>
          <div className="grid gap-6 sm:grid-cols-2">
            {locations.map((loc) => (
              <div key={loc.slug} className="rounded-lg border border-brand-100 p-5">
                <h2 className="font-semibold text-brand-800">{loc.name}</h2>
                <p className="mt-2 text-sm text-slate-600">{loc.address}</p>
                <p className="text-sm text-slate-600">Ph: {loc.phone}</p>
                <p className="text-sm text-slate-600">Fax: {loc.fax}</p>
                <p className="text-sm text-slate-600">{loc.email}</p>
              </div>
            ))}
          </div>
          <p className="mt-6 text-sm text-slate-500">
            Looking for after-hours help? See{" "}
            <Link to="/after-hours" className="underline hover:text-brand-700">
              when we're closed
            </Link>
            .
          </p>
        </div>

        <div>
          <h2 className="text-xl font-bold text-brand-900">General enquiries</h2>
          <div className="mt-4">
            <ContactForm />
          </div>
        </div>
      </div>
    </Layout>
  );
}
