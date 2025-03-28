require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Google OAuth සකසන්න
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URL = process.env.REDIRECT_URL || 'https://login-page-owner-dexter.onrender.com/auth/google/callback';
const APPROVED_REDIRECT = process.env.APPROVED_REDIRECT || 'https://login-page-owner-dexter.onrender.com/dashboard';
const REJECTED_REDIRECT = process.env.REJECTED_REDIRECT || 'https://login-page-owner-dexter.onrender.com/not-approved';

const client = new OAuth2Client(CLIENT_ID, CLIENT_SECRET, REDIRECT_URL);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// GitHub වෙතින් අනුමත ඊමේල් ලබා ගන්න
async function getApprovedEmails() {
  try {
    const response = await axios.get(process.env.APPROVED_EMAILS_URL || 
      'https://raw.githubusercontent.com/DEXTER-ID-PROJECT-POWER/DATA-JSON/refs/heads/main/buy-email.json');
    return response.data.approvedEmails;
  } catch (error) {
    console.error('GitHub ගොනුව ලබා ගැනීමේ දෝෂය:', error);
    return [];
  }
}

// Google ලොගින් URL ජනනය කරන්න
app.get('/auth/google', (req, res) => {
  const url = client.generateAuthUrl({
    access_type: 'offline',
    scope: ['profile', 'email'],
    prompt: 'select_account'
  });
  res.redirect(url);
});

// Google callback handler
app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;

  try {
    // Token ලබා ගන්න
    const { tokens } = await client.getToken(code);
    const idToken = tokens.id_token;

    // Token තහවුරු කරන්න
    const ticket = await client.verifyIdToken({
      idToken,
      audience: CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const userEmail = payload.email;

    // අනුමත ඊමේල් පරීක්ෂා කරන්න
    const approvedEmails = await getApprovedEmails();
    
    if (approvedEmails.includes(userEmail)) {
      // සාර්ථක ලොගින් - session එකේ ගබඩා කරන්න
      req.session.user = { email: userEmail, name: payload.name };
      req.session.save(() => {
        res.redirect(APPROVED_REDIRECT);
      });
    } else {
      // අනුමත නොවන ඊමේල්
      res.redirect(`${REJECTED_REDIRECT}?email=${encodeURIComponent(userEmail)}`);
    }
  } catch (error) {
    console.error('ලොගින් දෝෂය:', error);
    res.redirect(`${REJECTED_REDIRECT}?error=login_failed`);
  }
});

// Dashboard (අනුමත පරිශීලකයින් සඳහා)
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Not approved page
app.get('/not-approved', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'not-approved.html'));
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Static files
app.use(express.static('public'));

app.listen(port, () => {
  console.log(`සේවාදායකය ${port} වර්තයේ ධාවනය වෙමින් පවතී`);
});
