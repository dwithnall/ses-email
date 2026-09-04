export interface ServiceCategory {
  title: string;
  items: string[];
}

export const serviceCategories: ServiceCategory[] = [
  {
    title: "Everyday and Family Health",
    items: [
      "Standard consultations for single issues, script renewals, referrals, and results",
      "Children's health visits addressing illness, development, behaviour, and growth",
    ],
  },
  {
    title: "Chronic Conditions and Health Assessments",
    items: [
      "Structured management plans for diabetes, asthma, heart disease, arthritis",
      "Preventive health assessments for older patients and at-risk groups",
      "Weight and metabolic health consultations",
      "Heart Health Check (3-visit preventive screening for eligible adults)",
    ],
  },
  {
    title: "Women's Health and Reproductive Care",
    items: [
      "General women's health consultations",
      "Cervical screening, including self-collection options",
      "Contraception advice and device insertion/removal",
      "Pregnancy care and antenatal shared care",
    ],
  },
  {
    title: "Men's Health",
    items: [
      "Prostate, testicular, and cardiovascular concerns",
      "Weight and nutrition support",
      "Preventive check-ups",
    ],
  },
  {
    title: "Mental Health",
    items: [
      "Support for stress, anxiety, low mood, and sleep issues",
      "Mental Health Treatment Plans for psychology referrals",
    ],
  },
  {
    title: "Skin Surgery, Infusions, and Implants",
    items: [
      "Skin cancer checks and lesion removal",
      "Minor surgery and biopsies",
      "Ingrown toenail treatment",
      "Abscess drainage",
      "Foreign body removal",
      "Iron infusions",
    ],
  },
  {
    title: "Immunisations and Travel Medicine",
    items: [
      "Childhood, flu, COVID, shingles, and catch-up vaccines",
      "Travel medicine consultations",
    ],
  },
  {
    title: "Occupational Medicine",
    items: [
      "Work-related health assessments",
      "Pre-employment and return-to-work medicals",
    ],
  },
  {
    title: "Driver Medicals",
    items: ["Standard and heavy vehicle licence medicals"],
  },
  {
    title: "Nursing, Monitoring, and Diagnostics",
    items: ["ECG and Holter monitoring", "Spirometry testing", "Wound care and dressings"],
  },
  {
    title: "Pathology",
    items: ["Clinpath collection services at both locations"],
  },
];

export interface FeeRow {
  type: string;
  duration: string;
  totalFee: string;
  rebate: string;
  outOfPocket: string;
}

export const feeSchedule: FeeRow[] = [
  { type: "Brief", duration: "< 6 mins", totalFee: "$55.55", rebate: "$20.55", outOfPocket: "$35.00" },
  { type: "Standard (Level B)", duration: "< 20 mins", totalFee: "$95.05", rebate: "$45.05", outOfPocket: "$50.00" },
  { type: "Long (Level C)", duration: "< 40 mins", totalFee: "$147.10", rebate: "$87.10", outOfPocket: "$60.00" },
  { type: "Extended (Level D)", duration: "< 60 mins", totalFee: "$203.35", rebate: "$128.35", outOfPocket: "$75.00" },
  { type: "Comprehensive (Level E)", duration: "> 60 mins", totalFee: "$297.90", rebate: "$207.90", outOfPocket: "$90.00" },
];
