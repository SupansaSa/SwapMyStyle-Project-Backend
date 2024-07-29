const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 3000;

// Database connection setup
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'user_authentication',
  password: 'sanewKU81',
  port: 5432,
});

sgMail.setApiKey('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');

// Middleware setup
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads'); 
  },
  filename: function(req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname)); 
  }
});

const upload = multer({ storage: storage });

// Register User
app.post('/register', async (req, res) => {
  const { username, email, password, firstname, lastname, gender, dob, age, citizenId, phoneNumber, address, terms_accepted, data_usage_accepted, recover } = req.body;
  const verificationToken = crypto.randomBytes(32).toString('hex');
  try {
    if (!username || !email || !password || !firstname || !lastname || !gender || !dob || !age || !citizenId || !phoneNumber || !address || !recover) {
      return res.status(400).json({ success: false, message: 'Please provide all necessary information.' });
    }

    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'User already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (username, email, password, firstname, lastname, gender, dob, age, citizen_id, phone_number, address, verification_token, is_verified, terms_accepted, data_usage_accepted, recover) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING id',
      [username, email, hashedPassword, firstname, lastname, gender, dob, age, citizenId, phoneNumber, address, verificationToken, false, terms_accepted, data_usage_accepted, recover]
    );

    const userId = result.rows[0].id; // Get user ID
    const verificationLink = `http://192.168.31.218:3000/verify?token=${verificationToken}`;
    const msg = {
      to: email,
      from: 'supansak654@gmail.com',
      subject: 'ยืนยันอีเมล',
      text: `ลิงก์ยืนยัน: ${verificationLink}`,
      html: `<strong>คลิกลิงก์ที่นี่: <a href="${verificationLink}">${verificationLink}</a></strong>`,
    };
    await sgMail.send(msg);

    return res.status(201).json({ success: true, userId }); 
  } catch (err) {
    console.error('Error registering user', err.stack);
    return res.status(500).json({ success: false, message: 'Error registering user' });
  }
});

// Verify Email
app.get('/verify', async (req, res) => {
  const { token } = req.query;

  try {
    const result = await pool.query('UPDATE users SET is_verified = TRUE WHERE verification_token = $1 RETURNING *', [token]);

    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid or expired verification token' });
    }

    return res.status(200).json({ success: true, message: 'Email verified successfully' });
  } catch (err) {
    console.error('Error verifying email', err.stack);
    return res.status(500).json({ success: false, message: 'Error verifying email' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length > 0) {
      const user = result.rows[0];

      if (!user.is_verified) {
        return res.status(401).json({ success: false, message: 'กรุณายืนยันอีเมลก่อนเข้าสู่ระบบ' });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        return res.status(200).json({ success: true, user: { id: user.id } }); // Ensure the format of the response is correct
      } else {
        return res.status(401).json({ success: false, message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง โปรดลองใหม่อีกครั้ง' });
      }
    } else {
      return res.status(401).json({ success: false, message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
    }
  } catch (err) {
    console.error('Error logging in', err.stack);
    return res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ' });
  }
});



// Forget Password
app.post('/forget_password', async (req, res) => {
  const { email, recover } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND recover = $2', [email, recover]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'ไม่พบอีเมลในระบบ' });
    }

    return res.status(200).json({ success: true, message: 'ส่งรหัสรีเซ็ตรหัสผ่านไปยังอีเมลของคุณแล้ว' });
  } catch (err) {
    console.error('Error requesting password reset', err.stack);
    return res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการร้องขอรหัสรีเซ็ตรหัสผ่าน' });
  }
});

// Reset Password
app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 ', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'อีเมลไม่ถูกต้อง' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);

    return res.status(200).json({ success: true, message: 'รีเซ็ตรหัสผ่านสำเร็จ' });
  } catch (err) {
    console.error('Error resetting password', err.stack);
    return res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการรีเซ็ตรหัสผ่าน' });
  }
});

// Get Items by User ID
app.get('/getItems', async (req, res) => {
  const { userId } = req.query;

  try {
    const result = await pool.query('SELECT * FROM items WHERE user_id = $1', [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'No items found for this user' });
    }

    return res.status(200).json({ success: true, items: result.rows });
  } catch (err) {
    console.error('Error fetching items', err.stack);
    return res.status(500).json({ success: false, message: 'Error fetching items' });
  }
});

// Add Item
app.post('/addItem', upload.single('item_photo'), async (req, res) => {
  const { userId, item_name, item_type, item_detail, item_description } = req.body;
  const item_photo = req.file ? path.basename(req.file.path) : null;

  console.log('Received data:', req.body);
  console.log('Received file:', req.file);

  if (!userId) {
    return res.status(400).json({ success: false, message: 'Please provide user ID' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO items (user_id, item_name, item_type, item_detail, item_description, item_photo) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [userId, item_name || '', item_type || '', item_detail || '', item_description || '', item_photo]
    );

    const newItem = result.rows[0];

    return res.status(201).json({ success: true, item: newItem });
  } catch (err) {
    console.error('Error adding item', err.stack);
    return res.status(500).json({ success: false, message: 'Error adding item' });
  }
});


// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
