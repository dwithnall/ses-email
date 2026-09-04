import { Link } from "react-router-dom";
import Layout from "../components/Layout";

export default function NotFound() {
  return (
    <Layout>
      <div className="mx-auto max-w-xl px-4 py-24 text-center">
        <h1 className="text-3xl font-bold text-brand-900">Page not found</h1>
        <p className="mt-4 text-slate-600">
          Sorry, we couldn&rsquo;t find the page you were looking for.
        </p>
        <Link
          to="/"
          className="mt-6 inline-block rounded-md bg-brand-600 px-5 py-2.5 font-semibold text-white hover:bg-brand-700"
        >
          Back to home
        </Link>
      </div>
    </Layout>
  );
}
