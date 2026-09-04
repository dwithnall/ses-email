import { Link, useParams } from "react-router-dom";
import Layout from "../components/Layout";
import { team } from "../data/team";
import NotFound from "./NotFound";

export default function TeamMember() {
  const { slug } = useParams<{ slug: string }>();
  const member = team.find((m) => m.slug === slug);

  if (!member) return <NotFound />;

  return (
    <Layout>
      <div className="mx-auto max-w-3xl px-4 py-16">
        <Link to="/our-team" className="text-sm font-medium text-brand-700 hover:text-brand-900">
          &larr; Back to the team
        </Link>
        <h1 className="mt-4 text-3xl font-bold text-brand-900">{member.name}</h1>
        {member.qualifications && (
          <p className="mt-1 text-slate-500">{member.qualifications}</p>
        )}
        <p className="mt-1 text-sm font-medium uppercase tracking-wide text-brand-600">
          {member.group}
        </p>
        <p className="mt-6 text-slate-700">{member.focus}</p>
        <p className="mt-6 text-sm text-slate-500">
          To book an appointment with {member.name}, please use
          HotDoc via our{" "}
          <Link to="/appointments-and-fees" className="underline hover:text-brand-700">
            appointments &amp; fees
          </Link>{" "}
          page, or call your preferred location directly.
        </p>
      </div>
    </Layout>
  );
}
