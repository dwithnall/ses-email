import { Route, Routes } from "react-router-dom";
import Home from "./pages/Home";
import Services from "./pages/Services";
import OurTeam from "./pages/OurTeam";
import TeamMember from "./pages/TeamMember";
import AppointmentsAndFees from "./pages/AppointmentsAndFees";
import Contact from "./pages/Contact";
import LocationPage from "./pages/LocationPage";
import AfterHours from "./pages/AfterHours";
import Resources from "./pages/Resources";
import Newsletter from "./pages/Newsletter";
import News from "./pages/News";
import NewsPost from "./pages/NewsPost";
import PrivacyPolicy from "./pages/PrivacyPolicy";
import NotFound from "./pages/NotFound";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/services" element={<Services />} />
      <Route path="/our-team" element={<OurTeam />} />
      <Route path="/our-team/:slug" element={<TeamMember />} />
      <Route path="/appointments-and-fees" element={<AppointmentsAndFees />} />
      <Route path="/contact" element={<Contact />} />
      <Route path="/gumeracha" element={<LocationPage slug="gumeracha" />} />
      <Route path="/lobethal" element={<LocationPage slug="lobethal" />} />
      <Route path="/after-hours" element={<AfterHours />} />
      <Route path="/resources" element={<Resources />} />
      <Route path="/newsletter" element={<Newsletter />} />
      <Route path="/news" element={<News />} />
      <Route path="/news/:slug" element={<NewsPost />} />
      <Route path="/privacy-policy" element={<PrivacyPolicy />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
