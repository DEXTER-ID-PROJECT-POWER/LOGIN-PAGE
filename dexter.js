require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

const app = express();
const port = process.env.PORT || 3000;

// ආරක්ෂක middleware සකස් කිරීම
app.use(helmet());
app.use(cookieParser());

// අනුමත ලැයිස්තුව සඳහා rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // එක් IP එකකට උපරිම ඉල්ලීම්
});
app.use('/auth/google/callback', limiter);

// CSRF ආරක්ෂාව (පෝස්ට් ඉල්ලීම් සඳහා)
const csrfProtection = csrf({ cookie: true });

// Google OAuth සකස් කිරීම්
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URL = process.env.REDIRECT_URL || 'https://login-page-owner-dexter.onrender.com/auth/google/callback';
const APPROVED_REDIRECT = process.env.APPROVED_REDIRECT || 'https://login-page-owner-dexter.onrender.com/dashboard';
const REJECTED_REDIRECT = process.env.REJECTED_REDIRECT || 'https://login-page-owner-dexter.onrender.com/not-approved';

const client = new OAuth2Client(CLIENT_ID, CLIENT_SECRET, REDIRECT_URL);

// Session සකස් කිරීම්
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
}));

// අනුමත ඊමේල් ලබා ගැනීම සඳහා cache කිරීම
let approvedEmailsCache = [];
let cacheTimestamp = 0;
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

async function getApprovedEmails() {
  const now = Date.now();
  if (now - cacheTimestamp < CACHE_DURATION && approvedEmailsCache.length > 0) {
    return approvedEmailsCache;
  }

  try {
    const response = await axios.get(
      process.env.APPROVED_EMAILS_URL || 
      'https://raw.githubusercontent.com/DEXTER-ID-PROJECT-POWER/DATA-JSON/refs/heads/main/buy-email.json',
      { timeout: 5000 }
    );
    
    approvedEmailsCache = response.data.approvedEmails || [];
    cacheTimestamp = now;
    return approvedEmailsCache;
  } catch (error) {
    console.error('GitHub ගොනුව ලබා ගැනීමේ දෝෂය:', error);
    return approvedEmailsCache.length > 0 ? approvedEmailsCache : [];
  }
}

// Google ලොගින් URL ජනනය කිරීම
app.get('/auth/google', csrfProtection, (req, res) => {
  const state = req.csrfToken();
  req.session.authState = state;
  
  const url = client.generateAuthUrl({
    access_type: 'offline',
    scope: ['profile', 'email'],
    prompt: 'select_account',
    state: state
  });
  
  res.redirect(url);
});

// Google callback handler
app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;

  // දෝෂ පරීක්ෂාව
  if (error) {
    console.error('Google OAuth දෝෂය:', error);
    return res.redirect(`${REJECTED_REDIRECT}?error=oauth_error`);
  }

  // CSRF තහවුරු කිරීම
  if (!state || state !== req.session.authState) {
    console.error('CSRF token අසාර්ථක විය');
    return res.redirect(`${REJECTED_REDIRECT}?error=csrf_failed`);
  }

  try {
    // Token ලබා ගැනීම
    const { tokens } = await client.getToken(code);
    const idToken = tokens.id_token;

    // Token තහවුරු කිරීම
    const ticket = await client.verifyIdToken({
      idToken,
      audience: CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    const userEmail = payload.email;

    // අනුමත ඊමේල් පරීක්ෂාව
    const approvedEmails = await getApprovedEmails();
    
    if (approvedEmails.includes(userEmail)) {
      // සාර්ථක ලොගින්
      req.session.user = { 
        email: userEmail, 
        name: payload.name,
        picture: payload.picture,
        lastLogin: new Date()
      };
      
      // Session ගබඩා කිරීම
      req.session.save((err) => {
        if (err) {
          console.error('Session ගබඩා කිරීමේ දෝෂය:', err);
          return res.redirect(`${REJECTED_REDIRECT}?error=session_error`);
        }
        res.redirect(APPROVED_REDIRECT);
      });
    } else {
      // අනුමත නොවන ඊමේල්
      res.redirect(`${REJECTED_REDIRECT}?email=${encodeURIComponent(userEmail)}`);
    }
  } catch (err) {
    console.error('ලොගින් දෝෂය:', err);
    res.redirect(`${REJECTED_REDIRECT}?error=login_failed`);
  }
});

// API endpoint for client-side user verification
app.get('/api/user', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.json({ user: req.session.user });
});

// Dashboard
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'), {
    headers: {
      'Cache-Control': 'no-store'
    }
  });
});

// Not approved page
app.get('/not-approved', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'not-approved.html'));
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).sendFile(path.join(__dirname, 'public', 'error.html'));
});

// Static files with cache control
app.use(express.static('public', {
  maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0
}));

app.listen(port, () => {
  console.log(`සේවාදායකය ${port} වර්තයේ ධාවනය වෙමින් පවතී`);
});
