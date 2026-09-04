import { Link } from "react-router-dom";
import Layout from "../components/Layout";
import { locations } from "../data/locations";
import { serviceCategories } from "../data/services";

export default function Home() {
  return (
    <Layout>
      <section className="bg-brand-900 text-white">
        <div className="mx-auto max-w-6xl px-4 py-20 text-center">
          <h1 className="text-4xl font-bold sm:text-5xl">Give your health time</h1>
          <p className="mx-auto mt-4 max-w-2xl text-lg text-brand-100">
            Primary health care and chronic condition management from Specialist
            General Practitioners. Your GP in the Hills.
          </p>
          <p className="mx-auto mt-2 max-w-2xl text-brand-200">
            Two towns in the Hills, one team, with your health and wellbeing in mind.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-4">
            <Link
              to="/appointments-and-fees"
              className="rounded-md bg-white px-6 py-3 font-semibold text-brand-800 hover:bg-brand-50"
            >
              Book an appointment
            </Link>
            <Link
              to="/contact"
              className="rounded-md border border-white/60 px-6 py-3 font-semibold text-white hover:bg-white/10"
            >
              Contact us
            </Link>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-16">
        <h2 className="text-2xl font-bold text-brand-900">What you can expect</h2>
        <div className="mt-8 grid gap-8 sm:grid-cols-3">
          <div>
            <h3 className="font-semibold text-brand-700">Appropriate time</h3>
            <p className="mt-2 text-sm text-slate-600">
              Appointments are booked by duration rather than service type, so there's
              time to properly address what you came in for.
            </p>
          </div>
          <div>
            <h3 className="font-semibold text-brand-700">Transparent fees</h3>
            <p className="mt-2 text-sm text-slate-600">
              We offer mixed billing, and consultation fees are published in full, so
              you can check the cost before you book.
            </p>
          </div>
          <div>
            <h3 className="font-semibold text-brand-700">Respect and dignity</h3>
            <p className="mt-2 text-sm text-slate-600">
              Non-discriminatory care for everyone, with clear ways to give us
              feedback.
            </p>
          </div>
        </div>
      </section>

      <section className="bg-brand-50 py-16">
        <div className="mx-auto max-w-6xl px-4">
          <h2 className="text-2xl font-bold text-brand-900">What we do</h2>
          <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {serviceCategories.slice(0, 6).map((category) => (
              <div key={category.title} className="rounded-lg bg-white p-5 shadow-sm">
                <h3 className="font-semibold text-brand-800">{category.title}</h3>
              </div>
            ))}
          </div>
          <Link
            to="/services"
            className="mt-8 inline-block font-semibold text-brand-700 underline underline-offset-2 hover:text-brand-900"
          >
            See all services &rarr;
          </Link>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-16">
        <h2 className="text-2xl font-bold text-brand-900">Where to find us</h2>
        <div className="mt-8 grid gap-6 sm:grid-cols-2">
          {locations.map((loc) => (
            <div key={loc.slug} className="rounded-lg border border-brand-100 p-6">
              <h3 className="text-lg font-semibold text-brand-800">{loc.name}</h3>
              <p className="mt-2 text-sm text-slate-600">{loc.address}</p>
              <p className="text-sm text-slate-600">Ph: {loc.phone}</p>
              <p className="mt-2 text-sm text-slate-600">{loc.pathology}</p>
              <Link
                to={`/${loc.slug}`}
                className="mt-4 inline-block font-semibold text-brand-700 underline underline-offset-2 hover:text-brand-900"
              >
                Location details &rarr;
              </Link>
            </div>
          ))}
        </div>
      </section>
    </Layout>
  );
}
