import Layout from "../components/Layout";
import PageHeader from "../components/PageHeader";
import { resourceCategories } from "../data/news";

export default function Resources() {
  return (
    <Layout>
      <PageHeader title="Resources" subtitle="Trusted external resources on a range of health topics." />
      <div className="mx-auto max-w-4xl px-4 py-12">
        <div className="grid gap-6 sm:grid-cols-2">
          {resourceCategories.map((category) => (
            <div key={category.title} className="rounded-lg border border-brand-100 p-5">
              <h2 className="font-semibold text-brand-800">{category.title}</h2>
              <ul className="mt-3 space-y-1 text-sm">
                {category.links.map((link) => (
                  <li key={link.url}>
                    <a
                      href={link.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-brand-700 underline underline-offset-2 hover:text-brand-900"
                    >
                      {link.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </Layout>
  );
}
