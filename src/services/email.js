import nodemailer from 'nodemailer'

function transporter() {
  return nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT || '465', 10),
    secure: process.env.EMAIL_SECURE !== 'false',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  })
}

const FROM = () => process.env.EMAIL_FROM || 'noreply@snapie.io'
const BASE_URL = () => process.env.AUTH_BASE_URL || 'https://auth.snapie.io'

export async function sendSponsorInviteEmail(toEmail, note = null) {
  const registerUrl = `${BASE_URL()}/`
  const noteHtml = note
    ? `<p style="background:rgba(24,168,255,0.08);border:1px solid rgba(24,168,255,0.25);padding:10px 14px;border-radius:6px;font-size:0.88em;margin:16px 0;color:#66E4FF">${note}</p>`
    : ''
  const noteText = note ? `\n\nMessage: ${note}` : ''
  await transporter().sendMail({
    from: FROM(),
    to: toEmail,
    subject: "You've been invited to create a Hive account on Snapie",
    text: `You have a sponsored slot to create a free Hive blockchain account on Snapie.${noteText}\n\nRegister at: ${registerUrl}\n\nYour invitation is tied to ${toEmail} — register with this address and your sponsored slot will be applied automatically.\n\n—\nSnapie`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#06111f;color:#E8F4FF;padding:32px;border-radius:12px">
        <h2 style="color:#18A8FF;margin-bottom:16px">You've been invited!</h2>
        <p>You have a <strong>sponsored slot</strong> to create a free Hive blockchain account on Snapie.</p>
        ${noteHtml}
        <p>Click below to get started. Your invitation is tied to <strong>${toEmail}</strong> and will be applied automatically when you register with this address.</p>
        <a href="${registerUrl}" style="display:inline-block;background:#18A8FF;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;margin:20px 0">Create Your Hive Account</a>
        <p style="color:#888;font-size:0.85em">Make sure to register with <strong>${toEmail}</strong> to redeem your invitation.</p>
        <hr style="border:none;border-top:1px solid #1a3a5c;margin:24px 0">
        <p style="color:#aaa;font-size:0.8em">Snapie · auth.snapie.io</p>
      </div>
    `
  })
}

export async function sendVerificationEmail(toEmail, token) {
  const link = `${BASE_URL()}/api/auth/email/verify?token=${token}`
  await transporter().sendMail({
    from: FROM(),
    to: toEmail,
    subject: 'Confirm your Snapie email',
    text: `Click the link below to verify your email address and complete your Snapie registration.\n\n${link}\n\nThis link expires in 24 hours. If you didn't sign up, ignore this email.`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
        <h2 style="color:#18A8FF">Confirm your email</h2>
        <p>Click the button below to verify your email address and complete your Snapie registration.</p>
        <a href="${link}" style="display:inline-block;background:#18A8FF;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;margin:16px 0">Verify email</a>
        <p style="color:#888;font-size:0.85em">This link expires in 24 hours. If you didn't sign up for Snapie, you can safely ignore this email.</p>
        <hr style="border:none;border-top:1px solid #eee">
        <p style="color:#aaa;font-size:0.8em">Snapie · auth.snapie.io</p>
      </div>
    `
  })
}
