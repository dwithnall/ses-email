export interface TeamMember {
  slug: string;
  name: string;
  qualifications: string;
  group: "Specialist General Practitioners" | "General Practitioners" | "GP Registrar" | "Intern" | "Nursing Staff";
  focus: string;
}

export const team: TeamMember[] = [
  { slug: "dr-amos-maina", name: "Dr Amos Maina", qualifications: "MD, FRACGP", group: "Specialist General Practitioners", focus: "Men's health and chronic disease management" },
  { slug: "dr-chris-withnall", name: "Dr Chris Withnall", qualifications: "MBBS, FACRRM", group: "Specialist General Practitioners", focus: "Healthy ageing, sports rehabilitation, and weight management" },
  { slug: "dr-erich-heinzle", name: "Dr Erich Heinzle", qualifications: "MBBS, GDip OH&SM, FRACGP, FAFOEM", group: "Specialist General Practitioners", focus: "Occupational medicine and work-related injuries" },
  { slug: "dr-karen-williams", name: "Dr Karen Williams", qualifications: "BMBS, FRACGP", group: "Specialist General Practitioners", focus: "Women's and child health (not currently accepting new patients)" },
  { slug: "dr-parbati-gurung", name: "Dr Parbati Gurung", qualifications: "MBBS, FRACGP", group: "Specialist General Practitioners", focus: "Women's health, preventive care, and skin procedures" },
  { slug: "dr-shishir-gurung", name: "Dr Shishir Gurung", qualifications: "MBBS, MRCGP (UK)", group: "Specialist General Practitioners", focus: "General practice, chronic disease, and preventive health" },
  { slug: "dr-caroline-hampton", name: "Dr Caroline Hampton", qualifications: "MBChB, FRNZCGP", group: "General Practitioners", focus: "Family and women's/child health" },
  { slug: "dr-cephy-livera-camoens", name: "Dr Cephy Camoens", qualifications: "MD, MHSc, DFM", group: "General Practitioners", focus: "Women's health, menopause, diabetes, and skin procedures" },
  { slug: "dr-erika-nishimoto", name: "Dr Erika Nishimoto", qualifications: "MBBS, Dip.Occ.Med", group: "General Practitioners", focus: "Occupational medicine" },
  { slug: "dr-tara-tadiar", name: "Dr Tara Tadiar", qualifications: "BMBS, BSc(Hons)", group: "General Practitioners", focus: "Chronic disease, family medicine, and skin surgery" },
  { slug: "dr-alexander-horner", name: "Dr Alexander Horner", qualifications: "MBBCh, BHSc(Hons)", group: "GP Registrar", focus: "Obstetric shared care, paediatrics, and lifestyle medicine" },
  { slug: "dr-eisen-lin", name: "Dr Eisen Lin", qualifications: "", group: "Intern", focus: "Preventive health, chronic disease, and women's health" },
  { slug: "lisa-tilley", name: "Lisa Tilley", qualifications: "Nurse Manager", group: "Nursing Staff", focus: "Practice nursing leadership" },
  { slug: "beth-ladner", name: "Beth Ladner", qualifications: "Enrolled Nurse", group: "Nursing Staff", focus: "Practice nursing" },
  { slug: "calli-durant", name: "Calli Durant", qualifications: "Registered Nurse", group: "Nursing Staff", focus: "Practice nursing" },
  { slug: "helen-fordred", name: "Helen Fordred", qualifications: "Registered Nurse", group: "Nursing Staff", focus: "Practice nursing" },
  { slug: "julianna-boylan", name: "Julianna Boylan", qualifications: "Registered Nurse", group: "Nursing Staff", focus: "Practice nursing" },
  { slug: "kristie-foster", name: "Kristie Foster", qualifications: "Registered Nurse", group: "Nursing Staff", focus: "Practice nursing" },
  { slug: "melissa-pearce", name: "Melissa Pearce", qualifications: "Registered Nurse", group: "Nursing Staff", focus: "Practice nursing" },
];

export const teamGroupOrder: TeamMember["group"][] = [
  "Specialist General Practitioners",
  "General Practitioners",
  "GP Registrar",
  "Intern",
  "Nursing Staff",
];
