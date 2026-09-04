export interface Location {
  slug: "gumeracha" | "lobethal";
  name: string;
  address: string;
  phone: string;
  fax: string;
  email: string;
  hours: string[];
  hotdocUrl: string;
  pathology: string;
  description: string;
  history: string;
}

export const locations: Location[] = [
  {
    slug: "gumeracha",
    name: "Gumeracha",
    address: "29 Albert Street, Gumeracha SA 5233",
    phone: "(08) 8389 1009",
    fax: "(08) 8389 1655",
    email: "info@gummedical.com.au",
    hours: [
      "Monday to Friday: 8:30am–5:00pm",
      "Saturday: 8:30am–12:00pm",
      "Closed Sundays and public holidays",
    ],
    hotdocUrl:
      "https://www.hotdoc.com.au/medical-centres/gumeracha-SA-5233/gumeracha-medical-practice/doctors",
    pathology:
      "Clinpath pathology collection centre: 8:30am–12:00pm, Monday–Saturday, walk-in, no appointment needed.",
    description:
      "Ramped wheelchair access at the entrance. Parking is primarily on-street, with off-street spaces reserved for disabled permit holders.",
    history:
      "Formerly Gumeracha Medical Practice before merging with Lobethal Medical Centre in 2018. Many of our doctors live in the Hills, so the people sitting in our waiting room are often people we already know. Both locations share patient records, allowing flexibility in booking appointments at either site.",
  },
  {
    slug: "lobethal",
    name: "Lobethal",
    address: "5 Wattle Street, Lobethal SA 5241",
    phone: "(08) 8389 6364",
    fax: "(08) 8389 5400",
    email: "info@gummedical.com.au",
    hours: [
      "Reception hours 8:30am to 5:00pm Monday to Friday",
      "Closed weekends and public holidays",
    ],
    hotdocUrl:
      "https://www.hotdoc.com.au/medical-centres/lobethal-SA-5241/lobethal-medical-centre/doctors",
    pathology:
      "Clinpath pathology collection: Monday–Thursday by appointment; Friday walk-in clinic 8:30am–12pm.",
    description:
      "Ramped wheelchair access at the entrance. Parking is mainly on-street, with off-street spaces reserved for disabled permit holders.",
    history:
      "Merged with Gumeracha Medical Practice in 2018. One team now works across both towns, with unified patient records and billing. This location formerly operated as Lobethal Medical Centre and maintains continuity with the area's healthcare history through the Gumeracha District Soldiers' Memorial Hospital.",
  },
];
