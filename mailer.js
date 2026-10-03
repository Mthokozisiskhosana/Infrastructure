// ============================================
// EMAIL SENDING
// One sendMail({ from, to, subject, html }) used for every email the app
// sends (reset codes, staff invites, security alerts), with two backends:
//
//   - Brevo web API: used when BREVO_API_KEY is set (e.g. on Render).
//     It sends over HTTPS, which hosting providers don't block — unlike
//     SMTP ports, which free hosting plans often do.
//   - SMTP (Gmail etc.): used otherwise, e.g. when running on your own PC.
// ============================================

const nodemailer = require("nodemailer");

const DEFAULT_FROM = '"CIRIS Community Portal" <no-reply@communityportal.local>';
const BREVO_API_URL = process.env.BREVO_API_URL || "https://api.brevo.com/v3/smtp/email";

/** '"CIRIS" <me@gmail.com>' -> { name: "CIRIS", email: "me@gmail.com" }; plain addresses work too. */
function parseAddress(value) {
    const match = /^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/.exec(value || "");
    if (match) {
        const name = match[1].trim();
        return name ? { name, email: match[2].trim() } : { email: match[2].trim() };
    }
    return { email: String(value || "").trim() };
}

function createMailer() {
    const apiKey = process.env.BREVO_API_KEY;

    if (apiKey) {
        console.log("📧 Email: Brevo API");
        return {
            mode: "brevo",
            async sendMail({ from, to, subject, html }) {
                // The sender must be an address verified in Brevo (Senders & IPs)
                const sender = parseAddress(process.env.BREVO_SENDER || from || process.env.SMTP_FROM || DEFAULT_FROM);
                const res = await fetch(BREVO_API_URL, {
                    method: "POST",
                    headers: {
                        "api-key": apiKey,
                        "Content-Type": "application/json",
                        accept: "application/json"
                    },
                    body: JSON.stringify({ sender, to: [{ email: to }], subject, htmlContent: html }),
                    signal: AbortSignal.timeout(15000)
                });
                if (!res.ok) {
                    throw new Error(`Brevo rejected the email (${res.status}): ${await res.text()}`);
                }
                return res.json();
            }
        };
    }

    const port = Number(process.env.SMTP_PORT) || 587;
    console.log(`📧 Email: SMTP (${process.env.SMTP_HOST || "not configured"}:${port})`);
    const transport = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port,
        secure: port === 465,          // 465 = TLS from the start; 587 upgrades with STARTTLS
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        },
        // Fail within seconds instead of nodemailer's ~2 minute default, so a
        // blocked or unreachable mail server doesn't leave requests hanging.
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 15000
    });

    return {
        mode: "smtp",
        sendMail: options => transport.sendMail({ from: options.from || process.env.SMTP_FROM || DEFAULT_FROM, ...options })
    };
}

module.exports = { createMailer, parseAddress };
