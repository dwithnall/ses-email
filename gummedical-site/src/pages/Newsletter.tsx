import Layout from "../components/Layout";
import PageHeader from "../components/PageHeader";
import NewsletterForm from "../components/NewsletterForm";

export default function Newsletter() {
  return (
    <Layout>
      <PageHeader
        title="Newsletter"
        subtitle="Sign up to receive the latest Gum Medical updates by email — simply submit your details below."
      />
      <div className="mx-auto max-w-xl px-4 py-12">
        <NewsletterForm />
      </div>
    </Layout>
  );
}
