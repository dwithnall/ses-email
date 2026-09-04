import Layout from "../components/Layout";
import PageHeader from "../components/PageHeader";
import { serviceCategories } from "../data/services";

export default function Services() {
  return (
    <Layout>
      <PageHeader
        title="Services"
        subtitle="General practice covers most of medicine and health, so there are many ways in which we can assist. Care is delivered by specialist general practitioners registered with Australia's Medical Board."
      />
      <div className="mx-auto max-w-6xl px-4 py-12">
        <div className="grid gap-6 sm:grid-cols-2">
          {serviceCategories.map((category) => (
            <div key={category.title} className="rounded-lg border border-brand-100 p-6">
              <h2 className="font-semibold text-brand-800">{category.title}</h2>
              <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-slate-600">
                {category.items.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </Layout>
  );
}
