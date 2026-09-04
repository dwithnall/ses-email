import Layout from "../components/Layout";
import PageHeader from "../components/PageHeader";

const sections = [
  {
    heading: "About this policy",
    body: "Gum Medical Pty Ltd operates as an APP Entity under Australia's Privacy Act 1988. This policy explains how we handle personal information, sensitive information, and health records.",
  },
  {
    heading: "Collection",
    body: "We gather contact details, payment information, and health data (with consent) needed to deliver services and manage your account.",
  },
  {
    heading: "Use & disclosure",
    body: "Information is used for the purposes it was collected for. Third parties receive data only with consent or as legally required. Health information shared with other providers requires consent or is necessary for your treatment.",
  },
  {
    heading: "Access & accuracy",
    body: "You can request access to or correction of your information by contacting manager@gummedical.com.au. We respond within a reasonable timeframe.",
  },
  {
    heading: "Storage & security",
    body: "Your data is protected through encryption and SSL. Third-party data centres may store information overseas. We cannot guarantee 100% security.",
  },
  {
    heading: "Data breach notification",
    body: "We comply with Australia's Notifiable Data Breach Scheme, and will notify affected patients in a timely manner.",
  },
  {
    heading: "Anonymous healthcare",
    body: "You may request to interact with us anonymously, though Medicare rebates and prescriptions require identification.",
  },
  {
    heading: "Marketing communications",
    body: "You can opt out of marketing communications at any time. Account-related emails are still sent regardless of opt-out status.",
  },
  {
    heading: "Complaints",
    body: "If you have a complaint about how we've handled your information, contact our Practice Manager, or the Office of the Australian Information Commissioner.",
  },
];

export default function PrivacyPolicy() {
  return (
    <Layout>
      <PageHeader title="Privacy Policy" />
      <div className="mx-auto max-w-3xl space-y-8 px-4 py-12">
        {sections.map((section) => (
          <section key={section.heading}>
            <h2 className="text-lg font-bold text-brand-900">{section.heading}</h2>
            <p className="mt-2 text-sm text-slate-700">{section.body}</p>
          </section>
        ))}
      </div>
    </Layout>
  );
}
