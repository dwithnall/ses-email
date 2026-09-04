import { Link } from "react-router-dom";
import Layout from "../components/Layout";
import PageHeader from "../components/PageHeader";
import { newsPosts } from "../data/news";

export default function News() {
  return (
    <Layout>
      <PageHeader title="News" subtitle="Updates and articles from the Gum Medical team." />
      <div className="mx-auto max-w-3xl px-4 py-12">
        <ul className="divide-y divide-brand-100">
          {newsPosts.map((post) => (
            <li key={post.slug} className="py-4">
              <Link
                to={`/news/${post.slug}`}
                className="text-lg font-semibold text-brand-800 hover:text-brand-600"
              >
                {post.title}
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </Layout>
  );
}
