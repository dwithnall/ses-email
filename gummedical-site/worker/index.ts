export interface Env {
  ASSETS: Fetcher;
  RESEND_API_KEY: string;
  CONTACT_TO_EMAIL: string;
  CONTACT_FROM_EMAIL: string;
  NEWSLETTER_TO_EMAIL: string;
}

interface ContactPayload {
  firstName?: string;
  lastName?: string;
  email?: string;
  phone?: string;
  subject?: string;
  message?: string;
  company?: string; // honeypot
}

interface NewsletterPayload {
  firstName?: string;
  lastName?: string;
  email?: string;
  companyName?: string;
  company?: string; // honeypot
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function sendViaResend(
  env: Env,
  { to, from, replyTo, subject, html }: { to: string; from: string; replyTo?: string; subject: string; html: string },
): Promise<void> {
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to,
      reply_to: replyTo,
      subject,
      html,
    }),
  });

  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(`Resend API error (${response.status}): ${detail}`);
  }
}

async function handleContact(request: Request, env: Env): Promise<Response> {
  let payload: ContactPayload;
  try {
    payload = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid request body." }, 400);
  }

  // Honeypot: silently accept so bots don't learn it was rejected.
  if (payload.company) {
    return jsonResponse({ ok: true });
  }

  const { firstName, lastName, email, phone, subject, message } = payload;
  if (!firstName || !lastName || !email || !subject || !message) {
    return jsonResponse({ error: "Please fill in all required fields." }, 400);
  }
  if (!EMAIL_RE.test(email)) {
    return jsonResponse({ error: "Please provide a valid email address." }, 400);
  }

  try {
    await sendViaResend(env, {
      to: env.CONTACT_TO_EMAIL,
      from: env.CONTACT_FROM_EMAIL,
      replyTo: email,
      subject: `Website enquiry: ${subject}`,
      html: `
        <p><strong>Name:</strong> ${escapeHtml(firstName)} ${escapeHtml(lastName)}</p>
        <p><strong>Email:</strong> ${escapeHtml(email)}</p>
        <p><strong>Phone:</strong> ${escapeHtml(phone ?? "(not provided)")}</p>
        <p><strong>Subject:</strong> ${escapeHtml(subject)}</p>
        <p><strong>Message:</strong></p>
        <p>${escapeHtml(message).replace(/\n/g, "<br>")}</p>
      `,
    });
  } catch (err) {
    console.error("Failed to send contact email", err);
    return jsonResponse({ error: "Could not send your message right now. Please try again later." }, 502);
  }

  return jsonResponse({ ok: true });
}

async function handleNewsletter(request: Request, env: Env): Promise<Response> {
  let payload: NewsletterPayload;
  try {
    payload = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid request body." }, 400);
  }

  if (payload.company) {
    return jsonResponse({ ok: true });
  }

  const { firstName, lastName, email, companyName } = payload;
  if (!firstName || !lastName || !email) {
    return jsonResponse({ error: "Please fill in all required fields." }, 400);
  }
  if (!EMAIL_RE.test(email)) {
    return jsonResponse({ error: "Please provide a valid email address." }, 400);
  }

  try {
    await sendViaResend(env, {
      to: env.NEWSLETTER_TO_EMAIL,
      from: env.CONTACT_FROM_EMAIL,
      replyTo: email,
      subject: "New newsletter subscription",
      html: `
        <p><strong>Name:</strong> ${escapeHtml(firstName)} ${escapeHtml(lastName)}</p>
        <p><strong>Email:</strong> ${escapeHtml(email)}</p>
        <p><strong>Company:</strong> ${escapeHtml(companyName ?? "(not provided)")}</p>
      `,
    });
  } catch (err) {
    console.error("Failed to send newsletter signup email", err);
    return jsonResponse({ error: "Could not process your subscription right now. Please try again later." }, 502);
  }

  return jsonResponse({ ok: true });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/api/contact") {
      return handleContact(request, env);
    }

    if (request.method === "POST" && url.pathname === "/api/newsletter") {
      return handleNewsletter(request, env);
    }

    if (url.pathname.startsWith("/api/")) {
      return jsonResponse({ error: "Not found." }, 404);
    }

    return env.ASSETS.fetch(request);
  },
};
