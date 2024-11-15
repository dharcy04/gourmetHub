require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const sgMail = require('@sendgrid/mail');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));
app.use(helmet());

const PORT = process.env.PORT || 3000;
const mongoUri = process.env.MONGODB_URI || "mongodb+srv://asunciondharlin:JLag5OjsTUDHUhEm@cluster0.yclt2.mongodb.net/";

let usersCollection;

// MongoDB Client Initialization
const client = new MongoClient(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });
async function connectToDatabase() {
  try {
    await client.connect();
    console.log('Connected to MongoDB');
    const database = client.db('usersCollection');
    usersCollection = database.collection('usersCollection');
  } catch (err) {
    console.error('Failed to connect to MongoDB', err);
    process.exit(1);
  }
}
connectToDatabase();

// Set up SendGrid API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Hash Password function
function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hashSync(password, saltRounds);
}

// Generate Random String Function
function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

// Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json('Email is required');

  try {
    const resetToken = generateRandomString(32);
    await usersCollection.updateOne(
      { emaildb: email },
      { $set: { resetKey: resetToken, resetExpires: new Date(Date.now() + 3600000) } } // 1 hour expiry
    );

    res.status(200).json({ message: 'Password reset token generated and saved' });
  } catch (error) {
    console.error('Error processing forgot-password request:', error);
    res.status(500).json({ message: 'Error processing request' });
  }
});

// Send Reset Code Email
async function sendResetCodeEmail(email, resetCode) {
  const msg = {
    to: email,
    from: 'zaecramirez@gmail.com', // Ensure this email is verified with SendGrid
    subject: 'Your Password Reset Code',
    text: `Your password reset code is: ${resetCode}`,
    html: `<p>Your password reset code is:</p><h3>${resetCode}</h3>`,
  };

  try {
    await sgMail.send(msg);
    console.log(`Reset code email sent to ${email}`);
  } catch (error) {
    console.error('Error sending reset code email:', error);
    throw new Error('Error sending reset code email');
  }
}

// Generate 6-digit reset code
function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
}

// Send Password Reset Code
app.post('/send-password-reset', async (req, res) => {
  const { email } = req.body;

  try {
    console.log('Received email:', email); // Log the received email
    const user = await usersCollection.findOne({ emaildb: email });
    if (!user) {
      console.log('No account found for this email');
      return res.status(404).json({ message: 'No account with that email exists' });
    }

    const resetCode = generateCode(); // Generate a 6-digit reset code
    await usersCollection.updateOne(
      { emaildb: email },
      { $set: { resetKey: resetCode, resetExpires: new Date(Date.now() + 3600000) } }
    );

    // Send the reset code via email
    await sendResetCodeEmail(email, resetCode);

    res.json({ message: 'Password reset code sent', redirectUrl: '/reset-password.html' });
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ message: 'Error processing request' });
  }
});

// Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
  const { resetKey, newPassword } = req.body;

  try {
    const user = await usersCollection.findOne({
      resetKey: resetKey,
      resetExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset key.' });
    }

    const hashedPassword = hashPassword(newPassword);
    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { password: hashedPassword, resetKey: null, resetExpires: null } }
    );

    res.json({ success: true, message: 'Your password has been successfully reset.' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ success: false, message: 'Error resetting password' });
  }
});

// Sign Up Endpoint
app.post('/signup', async (req, res) => {
  const { email, password, nickname, favoriteFood } = req.body;

  try {
    if (!email || !password || !favoriteFood || !nickname) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const existingUser = await usersCollection.findOne({ emaildb: email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered.' });
    }

    function isValidPassword(password) {
      const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
      return passwordRegex.test(password);
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({ success: false, message: 'Password does not meet complexity requirements.' });
    }

    const hashedPassword = hashPassword(password);
    const newUser = {
      emaildb: email,
      nickname,
      favoriteFood,
      password: hashedPassword,
      createdAt: new Date(),
    };

    const insertResult = await usersCollection.insertOne(newUser);
    if (insertResult.acknowledged) {
      res.json({ success: true, message: 'Account created successfully!' });
    } else {
      res.status(500).json({ success: false, message: 'Failed to create account.' });
    }
  } catch (error) {
    console.error('Error creating account:', error);
    res.status(500).json({ success: false, message: 'An internal server error occurred.' });
  }
});

// Valid Password Check
function isValidPassword(password) {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
  return passwordRegex.test(password);
}

// Session management with MongoDB store
app.use(session({
secret: process.env.SESSION_SECRET, // Ensure you have a SESSION_SECRET in your .env file
resave: false,
saveUninitialized: false,
store: MongoStore.create({ mongoUrl: "mongodb+srv://asunciondharlin:JLag5OjsTUDHUhEm@cluster0.yclt2.mongodb.net/"}), // Use your MongoDB URI
cookie: {
secure: false, // Set to true if you're using HTTPS
httpOnly: true,
sameSite: 'lax',
maxAge: 1 * 60 * 1000 // Session expires after 30 minutes
}
}));
// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
if (req.session && req.session.userId) {
next();
} else {
res.status(401).json({ success: false, message: 'Unauthorized access.' });
}
}
// Fetch user details route
app.get('/user-details', isAuthenticated, async (req, res) => {
try {
const email = req.session.email;
if (!email) {
return res.status(401).json({ success: false, message: 'Unauthorized access.' });
}
// Fetch user details from the database
const user = await usersCollection.findOne(
{ emaildb: email },
{ projection: { emaildb: 1 } }
);
if (!user) {
return res.status(404).json({ success: false, message: 'User not found.' });
}
// Return only necessary details
res.json({
success: true,
user: {
email: user.emaildb
}
});
} catch (error) {
console.error('Error fetching user details:', error);
res.status(500).json({ success: false, message: 'Error fetching user details.' });
}
});
function isValidPassword(password) {
// Requires at least one uppercase letter, one lowercase letter, one number, and at least 8 characters

const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
return passwordRegex.test(password);
}


const loginLimiter = rateLimit({
windowMs: 1 * 60 * 1000, // 30 minutes
max: 5, // Limit each IP to 5 requests per windowMs
message: 'Too many login attempts, please try again after 1 minutes.',
handler: function (req, res, next, options) {
res.status(options.statusCode).json({ success: false, message: options.message });
}
});

app.post('/login', loginLimiter, async (req, res) => {
const { email, password } = req.body;
try {

// Input validation
if (!email || !password) {
return res.status(400).json({ success: false, message: 'Email and password are required.' });
}
if (!validator.isEmail(email)) {
return res.status(400).json({ success: false, message: 'Invalid email format.' });
}
// Fetch user
const user = await usersCollection.findOne({ emaildb: email });
if (!user) {
return res.status(400).json({ success: false, message: 'Invalid email or password.' });
}
// Account lockout check
if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 6000);

return res.status(403).json({ success: false, message: `Account is locked. Try again in ${remainingTime} minutes.` });
}
// Password verification
const passwordMatch = await bcrypt.compare(password, user.password);
if (!passwordMatch) {
// Handle failed attempts
let invalidAttempts = (user.invalidLoginAttempts || 0) + 1;
let updateFields = { invalidLoginAttempts: invalidAttempts };
if (invalidAttempts >= 3) {
// Lock account
updateFields.accountLockedUntil = new Date(Date.now() + 1 * 60 * 1000);

updateFields.invalidLoginAttempts = 10;
await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });

return res.status(403).json({ success: false, message: 'Account is locked due to multiple failed login attempts. Please try again after 30 minutes.' });

} else {
await usersCollection.updateOne({ _id: user._id }, { $set:

updateFields });

return res.status(400).json({ success: false, message: 'Invalid email or password.' });
}
}

// Successful login
await usersCollection.updateOne(
{ _id: user._id },
{ $set: { invalidLoginAttempts: 0, accountLockedUntil: null, lastLoginTime: new Date() } }
);
req.session.userId = user._id;
req.session.email = user.email;
req.session.role = user.role;
req.session.studentIDNumber = user.studentIDNumber;
await new Promise((resolve, reject) => {
req.session.save((err) => {
if (err) return reject(err);
resolve();
});
});
res.json({ success: true, role: user.role, message: 'Login successful!' });
} catch (error) {
console.error('Error during login:', error);
res.status(500).json({ success: false, message: 'Error during login.' });
}
});
app.post('/logout', async (req, res) => {
if (!req.session.userId) {
return res.status(400).json({ success: false, message: 'No user is logged in.' });
}
try {
req.session.destroy(err => {
if (err) {
console.error('Error destroying session:', err);
return res.status(500).json({ success: false, message: 'Logout failed.' });
}
res.clearCookie('connect.sid');
// Prevent caching
res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');

res.setHeader('Pragma', 'no-cache');
res.setHeader('Expires', '0');
res.setHeader('Surrogate-Control', 'no-store');
return res.json({ success: true, message: 'Logged out successfully.' });
});
} catch (error) {
console.error('Error during logout:', error);
return res.status(500).json({ success: false, message: 'Failed to log out.' });
}
});

// Start the Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
