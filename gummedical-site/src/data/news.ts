export interface NewsPost {
  slug: string;
  title: string;
}

export const newsPosts: NewsPost[] = [
  { slug: "prostate-testing-guidelines-2026", title: "If your brother or father had prostate cancer, testing now starts five years earlier" },
  { slug: "medicare-safety-net-family-registration", title: "The Medicare Safety Net, and the registration most couples have never done" },
  { slug: "what-makes-general-practice-its-own-specialty", title: "What makes general practice its own specialty" },
  { slug: "what-a-medical-internship-actually-is", title: "What a medical internship actually is, and why we host one" },
  { slug: "weight-loss-medicines-everyone-is-asking-about", title: "The weight-loss medicines everyone is asking about" },
  { slug: "the-tests-your-doctor-wont-order", title: "Not all tests are useful" },
  { slug: "mri-did-not-create-the-problem", title: "Why a scan may not be useful" },
];

export const resourceCategories = [
  {
    title: "Infectious Disease",
    links: [{ label: "Coronavirus basics and a guide to self-isolation", url: "https://www.healthdirect.gov.au/coronavirus-covid-19" }],
  },
  {
    title: "Women's Health",
    links: [{ label: "Jean Hailes Foundation", url: "https://www.jeanhailes.org.au/" }],
  },
  {
    title: "Paediatric Care",
    links: [{ label: "Kids Health Info — Royal Children's Hospital", url: "https://www.rch.org.au/kidsinfo/" }],
  },
  {
    title: "Travel Medicine",
    links: [{ label: "Travel Doctor (TMVC)", url: "https://www.traveldoctor.com.au/" }],
  },
  {
    title: "Mental Health Support",
    links: [
      { label: "Beyond Blue", url: "https://www.beyondblue.org.au/" },
      { label: "Relationships Australia (SA)", url: "https://www.rasa.org.au/" },
      { label: "Head to Health", url: "https://www.headtohealth.gov.au/" },
    ],
  },
  {
    title: "Condition-Specific Resources",
    links: [
      { label: "Allergy & Anaphylaxis Australia", url: "https://allergyfacts.org.au/" },
      { label: "MotherToBaby / Mothersafe", url: "https://www.mothersafe.org.au/" },
      { label: "Women's and Children's Health Network", url: "https://www.wchn.sa.gov.au/" },
      { label: "Diabetes SA", url: "https://diabetessa.org.au/" },
      { label: "Heart Foundation", url: "https://www.heartfoundation.org.au/" },
      { label: "Meningococcal Australia", url: "https://www.meningococcal.org.au/" },
    ],
  },
  {
    title: "General Health",
    links: [
      { label: "healthdirect", url: "https://www.healthdirect.gov.au/" },
      { label: "Eat for Health — Australian Dietary Guidelines", url: "https://www.eatforhealth.gov.au/" },
      { label: "SHINE SA", url: "https://www.shinesa.org.au/" },
    ],
  },
  {
    title: "Government Services",
    links: [
      { label: "My Aged Care", url: "https://www.myagedcare.gov.au/" },
      { label: "My Health Record", url: "https://www.myhealthrecord.gov.au/" },
    ],
  },
];
