import { Link, useParams } from "react-router-dom";
import Layout from "../components/Layout";
import { newsPosts } from "../data/news";
import NotFound from "./NotFound";

export default function NewsPost() {
  const { slug } = useParams<{ slug: string }>();
  const post = newsPosts.find((p) => p.slug === slug);

  if (!post) return <NotFound />;

  return (
    <Layout>
      <div className="mx-auto max-w-3xl px-4 py-16">
        <Link to="/news" className="text-sm font-medium text-brand-700 hover:text-brand-900">
          &larr; Back to news
        </Link>
        <h1 className="mt-4 text-3xl font-bold text-brand-900">{post.title}</h1>
        <div className="mt-6 rounded-md border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          The full article body for this post hasn&rsquo;t been migrated from WordPress
          yet — only the headline was captured during the site scrape. Copy the
          article text in here from the original CMS before publishing this page.
        </div>
      </div>
    </Layout>
  );
}
