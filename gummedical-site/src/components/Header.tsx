import { useState } from "react";
import { NavLink } from "react-router-dom";

const navLinks = [
  { to: "/", label: "Home" },
  { to: "/services", label: "Services" },
  { to: "/our-team", label: "Your Healthcare Team" },
  { to: "/appointments-and-fees", label: "Appointments & Fees" },
  { to: "/news", label: "News & Resources" },
  { to: "/after-hours", label: "When We're Closed" },
  { to: "/contact", label: "Contact" },
];

export default function Header() {
  const [open, setOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 border-b border-brand-100 bg-white/95 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
        <NavLink to="/" className="text-xl font-bold text-brand-800">
          Gum Medical
        </NavLink>

        <nav className="hidden lg:flex lg:items-center lg:gap-6">
          {navLinks.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === "/"}
              className={({ isActive }) =>
                `text-sm font-medium transition-colors hover:text-brand-600 ${
                  isActive ? "text-brand-700" : "text-slate-700"
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>

        <button
          type="button"
          className="lg:hidden"
          aria-label="Toggle navigation menu"
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
        >
          <span className="block h-0.5 w-6 bg-slate-800" />
          <span className="mt-1.5 block h-0.5 w-6 bg-slate-800" />
          <span className="mt-1.5 block h-0.5 w-6 bg-slate-800" />
        </button>
      </div>

      {open && (
        <nav className="flex flex-col gap-1 border-t border-brand-100 bg-white px-4 pb-4 lg:hidden">
          {navLinks.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === "/"}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                `rounded-md px-2 py-2 text-sm font-medium ${
                  isActive ? "bg-brand-50 text-brand-700" : "text-slate-700"
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
      )}
    </header>
  );
}
