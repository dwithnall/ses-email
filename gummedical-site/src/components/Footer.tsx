import { Link } from "react-router-dom";
import { locations } from "../data/locations";

export default function Footer() {
  return (
    <footer className="border-t border-brand-100 bg-brand-900 text-brand-50">
      <div className="mx-auto grid max-w-6xl gap-8 px-4 py-12 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <p className="text-lg font-bold text-white">Gum Medical</p>
          <p className="mt-2 text-sm text-brand-200">
            Primary health care and chronic condition management from Specialist
            General Practitioners. Your GP in the Hills.
          </p>
          <p className="mt-4 text-xs text-brand-300">
            We acknowledge the Traditional Owners of the land on which we work and
            pay our respects to Elders past and present.
          </p>
        </div>

        {locations.map((loc) => (
          <div key={loc.slug}>
            <p className="font-semibold text-white">{loc.name}</p>
            <p className="mt-2 text-sm text-brand-200">{loc.address}</p>
            <p className="text-sm text-brand-200">Ph: {loc.phone}</p>
            <p className="text-sm text-brand-200">Fax: {loc.fax}</p>
            <Link
              to={`/${loc.slug}`}
              className="mt-2 inline-block text-sm font-medium text-brand-100 underline underline-offset-2 hover:text-white"
            >
              Location details
            </Link>
          </div>
        ))}

        <div>
          <p className="font-semibold text-white">More</p>
          <ul className="mt-2 space-y-1 text-sm text-brand-200">
            <li><Link to="/resources" className="hover:text-white">Resources</Link></li>
            <li><Link to="/newsletter" className="hover:text-white">Newsletter</Link></li>
            <li><Link to="/privacy-policy" className="hover:text-white">Privacy Policy</Link></li>
          </ul>
          <div className="mt-4 flex gap-3 text-sm text-brand-200">
            <a href="https://www.facebook.com/" target="_blank" rel="noreferrer" className="hover:text-white">
              Facebook
            </a>
            <a href="https://www.instagram.com/" target="_blank" rel="noreferrer" className="hover:text-white">
              Instagram
            </a>
          </div>
        </div>
      </div>

      <div className="border-t border-brand-800 px-4 py-4 text-center text-xs text-brand-300">
        &copy; {new Date().getFullYear()} Gum Medical. All rights reserved.
      </div>
    </footer>
  );
}
