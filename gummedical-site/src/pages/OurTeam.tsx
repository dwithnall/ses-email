import { Link } from "react-router-dom";
import Layout from "../components/Layout";
import PageHeader from "../components/PageHeader";
import { team, teamGroupOrder } from "../data/team";

export default function OurTeam() {
  return (
    <Layout>
      <PageHeader
        title="Your Healthcare Team"
        subtitle="Our doctors and nurses across Gumeracha and Lobethal share patient records and work as one team."
      />
      <div className="mx-auto max-w-6xl space-y-12 px-4 py-12">
        {teamGroupOrder.map((group) => {
          const members = team.filter((m) => m.group === group);
          if (members.length === 0) return null;
          return (
            <div key={group}>
              <h2 className="text-xl font-bold text-brand-900">{group}</h2>
              <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {members.map((member) => (
                  <Link
                    key={member.slug}
                    to={`/our-team/${member.slug}`}
                    className="rounded-lg border border-brand-100 p-5 transition-colors hover:border-brand-300 hover:bg-brand-50"
                  >
                    <p className="font-semibold text-brand-800">{member.name}</p>
                    {member.qualifications && (
                      <p className="text-sm text-slate-500">{member.qualifications}</p>
                    )}
                    <p className="mt-2 text-sm text-slate-600">{member.focus}</p>
                  </Link>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </Layout>
  );
}
