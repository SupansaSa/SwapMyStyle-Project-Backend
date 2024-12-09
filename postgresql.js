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
  user: 'your_username',
  host: 'your_host',
  database: 'your_database',
  password: 'your_password',
  port: 'your_port',
});

// Set SendGrid API Key
sgMail.setApiKey('your_sendgrid_api_key');

// Middleware setup
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const isAdmin = (req, res, next) => {
  try {
    const { role } = req.user; // ดึงข้อมูล role จาก req.user (สมมติว่า JWT auth ได้กำหนดค่า req.user)

    if (role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied. Admins only.' });
    }

    next(); // ถ้าผู้ใช้เป็น admin ให้ทำงานถัดไป
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

const unbanAfterCooldown = async () => {
  const oneHourAgo = new Date(Date.now() - 1 * 60 * 60 * 1000); 

  try {
    
    const result = await pool.query(
      'UPDATE users SET is_banned = FALSE, ban_time = NULL WHERE is_banned = TRUE AND ban_time <= $1 RETURNING id, username, firstname, lastname',
      [oneHourAgo]
    );

    
    for (const user of result.rows) {
      const { id, username, firstname, lastname } = user;
      await pool.query(
        'INSERT INTO activity_log (activity_name, user_id, details) VALUES ($1, $2, $3)',
        [
          'autoUnbanUser',
          id,
          `User unbanned automatically: ${username} (${firstname} ${lastname})`
        ]
      );
    }
  } catch (err) {
    console.error('Error in unbanAfterCooldown:', err.stack);
  }
};


setInterval(unbanAfterCooldown, 60 * 60 * 1000); 


// checkBanStatus function
const checkBanStatus = async (req, res, next) => {
  const userId = req.body.userId; // หรือจาก session หรือ token

  try {
    const result = await pool.query('SELECT is_banned FROM users WHERE id = $1', [userId]); // ใช้ is_banned แทน status

    if (result.rows[0]?.is_banned) {
      return res.status(403).json({ message: 'User is banned' });
    }

    next(); // ให้ทำงานต่อถ้าผู้ใช้ไม่ถูกแบน
  } catch (error) {
    console.error('Error checking ban status:', error.stack);
    res.status(500).json({ message: 'Server error while checking ban status' });
  }
};



//บันทึกกิจกรรมลงฐานข้อมูล
const logActivity = async (userId, activityName, details) => {
  try {
    await pool.query(
      'INSERT INTO activity_log (user_id, activity_name, details) VALUES ($1, $2, $3)',
      [userId, activityName, details]
    );
    console.log('Activity logged:', activityName);
  } catch (err) {
    console.error('Error logging activity', err.stack);
  }
};


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

// multer สำหรับอัปโหลดรูปสินค้าหลายไฟล์
const itemStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/items/'); // โฟลเดอร์สำหรับจัดเก็บรูปสินค้า
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname); // ตั้งชื่อไฟล์ใหม่ด้วย timestamp
  }
});

const uploadItems = multer({
  storage: itemStorage,
  limits: { fileSize: 1024 * 1024 * 5 } // จำกัดขนาดไฟล์ 5MB
}).array('item_photo', 10); // ใช้ .array() สำหรับรูปภาพ ไม่ต้องมี 'delete_photos'

// ใช้งาน uploadItems ใน route ที่ต้องการ
app.post('/upload-items', uploadItems, (req, res) => {
  // logic to handle item images upload
  res.send('Item images uploaded successfully');
});


// Register User
app.post('/register', async (req, res) => {
  const { username, email, password, firstname, lastname, phoneNumber, terms_accepted, data_usage_accepted, recover } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000); 
  try {
    if (!username || !email || !password || !firstname || !lastname || !phoneNumber || !recover) {
      return res.status(400).json({ success: false, message: 'Please provide all necessary information.' });
    }

    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'User already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (username, email, password, firstname, lastname, phone_number, otp, is_verified, terms_accepted, data_usage_accepted, recover) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id',
      [username, email, hashedPassword, firstname, lastname, phoneNumber, otp, false, terms_accepted, data_usage_accepted, recover]
    );

    const userId = result.rows[0].id; // Get user ID
    const msg = {
      to: email,
      from: 'supansak654@gmail.com',
      subject: 'OTP Verification',
      text: `รหัส OTP เพื่อการยืนยันอีเมลของคุณคือ: ${otp}`,
      html: `<strong>รหัส OTP เพื่อการยืนยันอีเมลของคุณคือ: <span style="font-size: 24px;">${otp}</span></strong>`,
    };
    await sgMail.send(msg);

    return res.status(201).json({ success: true, userId });
  } catch (err) {
    console.error('Error registering user', err.stack);
    return res.status(500).json({ success: false, message: 'Error registering user' });
  }
});


// Verify OTP
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body; 

  try {
   
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid email or OTP' });
    }

    const user = result.rows[0];

   
    const otpCreatedAt = new Date(user.otp_created_at);
    const now = new Date();
    const oneMinute = 60 * 1000; 

    if (now - otpCreatedAt > oneMinute) {
      return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new OTP.' });
    }

   
    if (user.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid email or OTP' });
    }

   
    await pool.query('UPDATE users SET is_verified = TRUE, otp = NULL WHERE email = $1', [email]);

    return res.status(200).json({ success: true, message: 'OTP verified successfully' });
  } catch (err) {
    console.error('Error verifying OTP', err.stack);
    return res.status(500).json({ success: false, message: 'Error verifying OTP' });
  }
});

app.post('/resend-otp', async (req, res) => {
  const { email } = req.body;
console.log(req.body)
  try {
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }
    

    const otp = Math.floor(100000 + Math.random() * 900000); 

    
    await pool.query('UPDATE users SET otp = $1, is_verified = $2 WHERE email = $3', [otp, false, email]);

   
    const msg = {
      to: email,
      from: 'supansak654@gmail.com',
      subject: 'Your New OTP Code',
      text: `Your new OTP code is: ${otp}`,
      html: `<strong>Your new OTP code is: <span style="font-size: 24px;">${otp}</span></strong>`,
    };
    await sgMail.send(msg);

    return res.status(200).json({ success: true, message: 'OTP sent successfully.' });
  } catch (err) {
    console.error('Error resending OTP', err.stack);
    return res.status(500).json({ success: false, message: 'Error resending OTP' });
  }
});



//เกี่ยวกับรีเซ็ต password แบบใช้ OTP**********************************************************************************
// Send OTP for password recovery
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000); // สร้าง OTP 6 หลัก

  try {
    if (!email) {
      return res.status(400).json({ success: false, message: 'Please provide an email.' });
    }

    
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'User does not exist.' });
    }

    
    const msg = {
      to: email,
      from: 'supansak654@gmail.com',
      subject: 'OTP for Recovery Password ',
      text: `Your OTP code is: ${otp}`,
      html: `<strong>Your OTP code is: <span style="font-size: 24px;">${otp}</span></strong>`,
    };
    await sgMail.send(msg);

   
    await pool.query('UPDATE users SET otp = $1, is_verified = $2 WHERE email = $3', [otp, false, email]);

    return res.status(200).json({ success: true, message: 'OTP sent successfully.' });
  } catch (err) {
    console.error('Error sending OTP', err.stack);
    return res.status(500).json({ success: false, message: 'Error sending OTP' });
  }
});


app.post('/verify-password-otp', async (req, res) => {
  const { email, otp } = req.body; 

  try {
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

   
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid email or OTP' });
    }

    const user = result.rows[0];

   
    console.log(`Stored OTP: ${user.otp}, Provided OTP: ${otp}`); 

   
    if (user.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid email or OTP' });
    }

  
    await pool.query('UPDATE users SET is_verified = TRUE, otp = NULL WHERE email = $1', [email]);

    return res.status(200).json({ success: true, message: 'OTP verified successfully. You can now reset your password.' });
  } catch (err) {
    console.error('Error verifying OTP', err.stack);
    return res.status(500).json({ success: false, message: 'Error verifying OTP' });
  }
});





app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    // ค้นหาผู้ใช้ที่มี email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'User not found.' });
    }

    const userId = result.rows[0].id;

    // เปลี่ยนรหัสผ่านใหม่ (คุณควรเข้ารหัสรหัสผ่านด้วย bcrypt)
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);

    return res.status(200).json({ success: true, message: 'Password reset successfully.' });
  } catch (err) {
    console.error('Error resetting password', err.stack);
    return res.status(500).json({ success: false, message: 'Error resetting password' });
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
        
        await logActivity(user.id, 'Login', 'User logged in');

       
        return res.status(200).json({ 
          success: true, 
          user: { id: user.id, role: user.role } 
        });
      } else {
        return res.status(401).json({ success: false, message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
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
    const result = await pool.query('SELECT * FROM items WHERE user_id = $1  AND is_deleted = FALSE', [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'No items found for this user' });
    }

    return res.status(200).json({ success: true, items: result.rows });
  } catch (err) {
    console.error('Error fetching items', err.stack);
    return res.status(500).json({ success: false, message: 'Error fetching items' });
  }
});

// Update User Profile with Profile Photo
app.post('/updateProfile', upload.single('profile_image'), async (req, res) => {
  const { userId, username, firstname, lastname } = req.body;
  const profile_image = req.file ? path.basename(req.file.path) : null;

  if (!userId || !username || !firstname || !lastname) {
    return res.status(400).json({ success: false, message: 'User ID, username, firstname, and lastname are required' });
  }

  try {
    
    const oldProfileResult = await pool.query('SELECT profile_photo FROM users WHERE id = $1', [userId]);
    const oldProfilePhoto = oldProfileResult.rows[0].profile_photo;

    
    const updatedProfileImage = profile_image || oldProfilePhoto; 

    const result = await pool.query(
      'UPDATE users SET username = $1, firstname = $2, lastname = $3, profile_photo = $4 WHERE id = $5 RETURNING username, firstname, lastname, profile_photo',
      [username, firstname, lastname, updatedProfileImage, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

   
    await logActivity(userId, 'Update Profile', 'User Update Profile');

    return res.status(200).json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('Error updating profile', err.stack);
    return res.status(500).json({ success: false, message: 'Error updating profile' });
  }
});


// Get User Profile
app.get('/getUserProfile', async (req, res) => {
  const { userId } = req.query;

  if (!userId) {
    return res.status(400).json({ success: false, message: 'User ID is required' });
  }

  console.log('Fetching user profile for userId:', userId);

  try {
    const result = await pool.query(`
      SELECT 
        u.username, 
        u.firstname, 
        u.lastname, 
        u.profile_photo, 
        COALESCE(SUM(cp.points), 0) AS credit_points,
        COALESCE((SELECT SUM(dp.points) FROM discredit_points dp WHERE dp.user_id = u.id), 0) AS discredit_points
      FROM 
        users u
      LEFT JOIN 
        credit_points cp ON u.id = cp.user_id
      WHERE 
        u.id = $1
      GROUP BY 
        u.id
    `, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const user = result.rows[0];
    const profilePhotoUrl = user.profile_photo ? `http://10.34.103.89:3000/uploads/${user.profile_photo}` : null;

    return res.status(200).json({
      success: true,
      username: user.username,
      firstname: user.firstname,
      lastname: user.lastname,
      profile_photo: profilePhotoUrl,
      credit_points: parseInt(user.credit_points),  
      discredit_points: parseInt(user.discredit_points), 
    });
  } catch (err) {
    console.error('Error fetching user profile', err.stack);
    return res.status(500).json({ success: false, message: 'Error fetching user profile' });
  }
});





// เพิ่มส่วนนี้ใน Route ของ /addItem
app.post('/addItem', uploadItems, async (req, res) => {
  const { userId, item_name, item_type, item_description, item_price } = req.body;

  
  const item_photos = req.files ? req.files.map(file => path.basename(file.path)) : []; 

  console.log('Received data:', req.body);
  console.log('Received files:', req.files);

  if (!userId) {
    return res.status(400).json({ success: false, message: 'Please provide user ID' });
  }

  try {
    
    const result = await pool.query(
      'INSERT INTO items (user_id, item_name, item_type, item_description, item_photo, item_price) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [userId, item_name || '', item_type || '', item_description || '', JSON.stringify(item_photos), item_price]
    );

    const newItem = result.rows[0];

    
    await pool.query(
      'INSERT INTO activity_log (user_id, activity_name, activity_time, details) VALUES ($1, $2, $3, $4)',
      [userId, 'Add Item', new Date(), `Added item: ${item_name}`]
    );

    return res.status(201).json({ success: true, item: newItem });
  } catch (err) {
    console.error('Error adding item', err.stack);
    return res.status(500).json({ success: false, message: 'Error adding item' });
  }
});



// Get Items by Category
app.get('/getItemsByType', async (req, res) => {
  const { itemType, userId } = req.query;

 
  if (!itemType || !userId) {
    return res.status(400).json({ success: false, message: 'Missing itemType or userId' });
  }

  try {
    
    const result = await pool.query(
      'SELECT * FROM items WHERE item_type = $1 AND is_locked = false AND user_id != $2 AND is_deleted = FALSE',
      [itemType, userId]
    );

    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'No items found for this category' });
    }

   
    return res.status(200).json({ success: true, items: result.rows });
  } catch (err) {
    console.error('Error fetching items', err.stack);
    return res.status(500).json({ success: false, message: 'Error fetching items', error: err.message });
  }
});



// Retrieve all product information excluding user's own items
app.get('/getAllItems', async (req, res) => {
  const userId = req.query.userId; // รับ userId จาก query parameter


  try {
    
    const result = await pool.query(
      'SELECT * FROM items WHERE is_locked = false AND user_id != $1 AND is_deleted = FALSE',
      [userId]
    );

   
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'ไม่พบสินค้าที่ตรงกับเงื่อนไข' });
    }

    
    return res.status(200).json({ success: true, items: result.rows });
  } catch (err) {
    console.error('Error fetching items', err.stack);
    return res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า' });
  }
});



app.get('/getAllItemadmin', async (req, res) => {
  //const userId = req.query.userId; // รับ userId จาก query parameter


  try {
    
    const result = await pool.query(
      'SELECT * FROM items WHERE is_locked = false ',
      //[userId]
    );

   
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'ไม่พบสินค้าที่ตรงกับเงื่อนไข' });
    }
    console.log(result)
    
    return res.status(200).json({ success: true, items: result.rows });
  } catch (err) {
    console.error('Error fetching items', err.stack);
    return res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า' });
  }
});



// Search Items 
// Endpoint to search items with filters
app.get('/searchItems', async (req, res) => {
  const { q, itemType, minPrice, maxPrice } = req.query;
  let query = 'SELECT * FROM items WHERE is_locked = false AND is_deleted = FALSE'; 
  let params = [];

  if (q) {
    params.push(`%${q}%`);
    query += ` AND item_name ILIKE $${params.length}`;
  }

  if (itemType) {
    params.push(itemType);
    query += ` AND item_type = $${params.length}`;
  }

  if (minPrice) {
    params.push(parseFloat(minPrice));
    query += ` AND item_price >= $${params.length}`;
  }

  if (maxPrice) {
    params.push(parseFloat(maxPrice));
    query += ` AND item_price <= $${params.length}`;
  }

  try {
    const result = await pool.query(query, params);
    res.json({ success: true, items: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});





// อัปเดตข้อมูลรายการ
app.put('/updateItem/:id', uploadItems, checkBanStatus, async (req, res) => {
  const { id } = req.params;
  const { userId, item_name, item_type, item_price, item_description, delete_photos } = req.body; 

  let item_photos = [];

  
  const existingItem = await pool.query('SELECT item_photo FROM items WHERE id = $1', [id]);
  let existingPhotos = existingItem.rows[0].item_photo || [];

  
  if (typeof existingPhotos === 'string') {
    try {
      existingPhotos = JSON.parse(existingPhotos);
    } catch (err) {
      console.error('Failed to parse existing photos:', err);
      existingPhotos = [];
    }
  }

  
  if (delete_photos) {
    const photosToDelete = JSON.parse(delete_photos);
    photosToDelete.forEach((photo) => {
      const filePath = `uploads/items/${photo}`;
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`Deleted file: ${filePath}`);
      } else {
        console.log(`File not found, cannot delete: ${filePath}`);
      }
      existingPhotos.splice(existingPhotos.indexOf(photo), 1);
    });
  }

  if (req.files) {
    req.files.forEach((file) => {
      item_photos.push(file.filename);  
    });
  }

  item_photos = [...existingPhotos, ...item_photos];

  try {
   
    const updatedItem = await pool.query(
      'UPDATE items SET item_name = $1, item_type = $2, item_price = $3, item_description = $4, item_photo = $5 WHERE id = $6 RETURNING *',
      [item_name, item_type, item_price, item_description, JSON.stringify(item_photos), id]
    );

    if (updatedItem.rowCount > 0) {
      console.log(`Item ${id} updated successfully`);

    
      console.log('User ID:', userId); 

      
      await pool.query(
        'INSERT INTO activity_log (user_id, activity_name, activity_time, details) VALUES ($1, $2, $3, $4)',
        [userId, 'Update Item', new Date(), `Updated item: ${item_name}`]
      );

      res.json({ success: true, item: updatedItem.rows[0] });
    } else {
      console.log(`Item ${id} not found for update`);
      res.json({ success: false, message: 'Item not found' });
    }
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});



app.delete('/deleteItem/:item_id', checkBanStatus, async (req, res) => {
  const { item_id } = req.params;
  const userId = req.query.userId;

  if (!userId) {
    return res.status(400).json({ success: false, message: 'Please provide user ID' });
  }

  try {
    
    const itemResult = await pool.query('SELECT * FROM items WHERE id = $1', [item_id]);

    if (itemResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }

    
    const deleteResult = await pool.query('DELETE FROM items WHERE id = $1', [item_id]);

    if (deleteResult.rowCount > 0) {
     
      await pool.query(
        'INSERT INTO activity_log (user_id, activity_name, activity_time, details) VALUES ($1, $2, $3, $4)',
        [userId, 'Delete Item', new Date(), `Deleted item with ID: ${item_id}`]
      );

      return res.status(200).json({ success: true, message: 'Item deleted successfully', status: true });
    } else {
      return res.status(500).json({ success: false, message: 'Failed to delete item', status: false });
    }
  } catch (err) {
    console.error('Error deleting item:', err.stack);
    return res.status(500).json({ success: false, message: 'Internal Server Error', status: false });
  }
});





// API สำหรับการแลกเปลี่ยนสินค้า
app.post('/exchanges', checkBanStatus, async (req, res) => {
  const { itemId, userId, selectedItemId } = req.body; 

 
  if (!itemId || !userId || !selectedItemId) {
    return res.status(400).send('ข้อมูลไม่ถูกต้อง: ต้องการ itemId, userId และ selectedItemId');
  }

  
  if (isNaN(itemId) || isNaN(userId) || isNaN(selectedItemId)) {
    return res.status(400).send('ข้อมูลไม่ถูกต้อง: itemId, userId และ selectedItemId ต้องเป็นตัวเลข');
  }

  try {
    
    const ownerResult = await pool.query('SELECT user_id AS owner_id FROM items WHERE id = $1', [itemId]);
    if (ownerResult.rows.length === 0) {
      return res.status(404).send('ไม่พบสินค้า');
    }
    const ownerId = ownerResult.rows[0].owner_id;

    
    const usernameResult = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
    if (usernameResult.rows.length === 0) {
      return res.status(404).send('ไม่พบผู้ใช้');
    }
    const username = usernameResult.rows[0].username;

   
    const result = await pool.query(
        'INSERT INTO exchanges (exchanger_id, owner_id, item_id, selected_item_id, status, created_at) VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *',
        [userId, ownerId, itemId, selectedItemId, 'pending'] 
    );

    
    if (result.rows.length === 0) {
      return res.status(500).send('ไม่สามารถสร้างคำขอแลกเปลี่ยนได้');
    }

   
    const ownerMessage = `${username}\nต้องการแลกเปลี่ยนสินค้ากับคุณ`;

   
    const ownerNotification = await pool.query(
        'INSERT INTO notifications (user_id, message, exchanger_id) VALUES ($1, $2, $3) RETURNING *',
        [ownerId, ownerMessage, result.rows[0].id] 
    );

   
    if (ownerNotification.rows.length === 0) {
      return res.status(500).send('ไม่สามารถส่งการแจ้งเตือนให้เจ้าของสินค้าได้');
    }

    
    await logActivity(userId, 'Exchanged', `ItemID: ${itemId}, SelectedItemID: ${selectedItemId}`);

    
    io.to(ownerId).emit('notification', ownerMessage); 
    io.to(userId).emit('notification', 'คำขอแลกสินค้าของคุณถูกส่งเรียบร้อยแล้ว');

   
    return res.send('คำขอแลกเปลี่ยนถูกส่งเรียบร้อยแล้ว');
  } catch (error) {
    console.error('Error:', error);
    return res.status(500).send('ข้อผิดพลาดภายในเซิร์ฟเวอร์');
  }
});



app.post('/exchanges/accept', async (req, res) => {
  const { exchangeId, ownerId, selectedItemId } = req.body;

  console.log('exchangeId:', exchangeId);
  console.log('ownerId:', ownerId);
  console.log('selectedItemId:', selectedItemId);

  if (!exchangeId || isNaN(exchangeId) || !ownerId || isNaN(ownerId) || !selectedItemId || isNaN(selectedItemId)) {
    return res.status(400).send('ข้อมูลไม่ถูกต้อง: ต้องการ exchangeId, ownerId, และ selectedItemId');
  }

  try {
   
    const exchangeResult = await pool.query(
      'SELECT * FROM exchanges WHERE id = $1 AND owner_id = $2 AND selected_item_id = $3',
      [exchangeId, ownerId, selectedItemId]
    );

    console.log('exchangeResult:', exchangeResult.rows);

    if (exchangeResult.rows.length === 0) {
      return res.status(404).send('ไม่พบการแลกเปลี่ยน หรือ selectedItemId ไม่ตรงกัน');
    }

    const exchange = exchangeResult.rows[0];

    
    const result = await pool.query(
      'UPDATE exchanges SET status = $1, owner_confirmed_at = NOW() WHERE id = $2',
      ['accepted', exchangeId]
    );

    if (result.rowCount === 0) {
      return res.status(500).send('ไม่สามารถอัปเดตสถานะการแลกเปลี่ยนได้');
    }

    
    await pool.query('UPDATE items SET is_locked = TRUE WHERE id = $1', [exchange.item_id]);

   
    await pool.query('UPDATE items SET is_locked = TRUE WHERE id = $1', [selectedItemId]);

    
    await pool.query(
      'UPDATE exchanges SET status = $1 WHERE item_id = $2 AND status != $3',
      ['cancelled', exchange.selected_item_id, 'accepted']
    );

    const userMessage = "คำขอแลกเปลี่ยนของคุณได้รับการยอมรับเรียบร้อยแล้ว";
    try {
      
      await pool.query(
        'INSERT INTO notifications (user_id, message, exchanger_id, action_status) VALUES ($1, $2, $3, $4)',
        [exchange.exchanger_id, userMessage, exchangeId, true] 
      );
      console.log('Notification added for user:', exchange.exchanger_id);
    } catch (insertError) {
      console.error('Error adding notification:', insertError);
      return res.status(500).send('ไม่สามารถเพิ่มการแจ้งเตือนได้');
    }

    
    io.to(exchange.exchanger_id).emit('notification', userMessage);

    return res.send('คำขอแลกเปลี่ยนได้รับการยอมรับเรียบร้อยแล้ว');
  } catch (error) {
    console.error('Error:', error);
    return res.status(500).send('ข้อผิดพลาดภายในเซิร์ฟเวอร์');
  }
});


app.post('/exchanges/reject', async (req, res) => {
  const { exchangeId, ownerId, selectedItemId } = req.body;

  console.log('Reject request - exchangeId:', exchangeId);
  console.log('Reject request - ownerId:', ownerId);
  console.log('Reject request - selectedItemId:', selectedItemId);

  if (!exchangeId || isNaN(exchangeId) || !ownerId || isNaN(ownerId) || !selectedItemId || isNaN(selectedItemId)) {
    return res.status(400).send('ข้อมูลไม่ถูกต้อง: ต้องการ exchangeId, ownerId, และ selectedItemId');
  }

  try {
   
    const exchangeResult = await pool.query(
      'SELECT * FROM exchanges WHERE id = $1 AND owner_id = $2 AND selected_item_id = $3',
      [exchangeId, ownerId, selectedItemId]
    );

    console.log('exchangeResult:', exchangeResult.rows);

    if (exchangeResult.rows.length === 0) {
      return res.status(404).send('ไม่พบการแลกเปลี่ยน หรือ selectedItemId ไม่ตรงกัน');
    }

    const exchange = exchangeResult.rows[0];

   
    const result = await pool.query('UPDATE exchanges SET status = $1 WHERE id = $2', ['rejected', exchangeId]);

    if (result.rowCount === 0) {
      return res.status(500).send('ไม่สามารถอัปเดตสถานะการแลกเปลี่ยนได้');
    }

    
    const userMessage = `คำขอแลกเปลี่ยนของคุณถูกปฏิเสธ`;
    try {
      
      await pool.query(
        'INSERT INTO notifications (user_id, message, exchanger_id, action_status) VALUES ($1, $2, $3, $4)',
        [exchange.exchanger_id, userMessage, exchangeId, false] 
      );
      console.log('Notification added for user:', exchange.exchanger_id);
    } catch (insertError) {
      console.error('Error adding notification:', insertError);
      return res.status(500).send('ไม่สามารถเพิ่มการแจ้งเตือนได้');
    }

   
    io.to(exchange.exchanger_id).emit('notification', userMessage);

    return res.send('คำขอแลกเปลี่ยนถูกปฏิเสธแล้ว');
  } catch (error) {
    console.error('Error:', error);
    return res.status(500).send('ข้อผิดพลาดภายในเซิร์ฟเวอร์');
  }
});





// API สำหรับดึงประวัติการแลกเปลี่ยน 
app.get('/swapsss/:userId', async (req, res) => { 
  const { userId } = req.params; // รับ userId จากพารามิเตอร์
  console.log(`Received request for userId: ${userId}`); 

  try {
    const query = 
      `SELECT 
        e.id AS exchange_id,
        e.exchanger_id,
        e.owner_id,
        e.item_id,
        e.status,
        e.created_at,
        e.selected_item_id,
        i.item_name,
        i.item_price,
        i.item_photo,
        e.exchange_result  
      FROM exchanges e
      JOIN items i ON e.item_id = i.id
      WHERE e.exchanger_id = $1 OR e.owner_id = $1`;
    
    console.log('Executing query:', query);
    const { rows } = await pool.query(query, [userId]); 

    console.log('Fetched data from database:', rows);

    
    const formattedData = rows.map(item => ({
      id: item.exchange_id,
      itemName: item.item_name,
      itemPrice: item.item_price,
      itemPhoto: item.item_photo,
      createdAt: item.created_at,
      exchangeResult: item.exchange_result, 
    }));

    res.json(formattedData); 
  } catch (error) {
    console.error('Error fetching data:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



app.get('/swapsDetails/:exchangeId', async (req, res) => {
  const exchangeId = req.params.exchangeId;
  try {
      const result = await pool.query(`
          SELECT 
              exchanges.id AS exchange_id,
              exchanges.status,
              exchanges.created_at,
              exchanges.owner_confirmed_at, 
              items.item_name AS exchange_item_name,
              items.item_type AS exchange_item_type,
              items.item_photo AS exchange_item_photo,
              items.item_price AS exchange_item_price,
              selected_items.item_name AS selected_item_name,
              selected_items.item_photo AS selected_item_photo,
              selected_items.item_price AS selected_item_price,
              exchanger.username AS exchanger_username,
              exchanger.profile_photo AS exchanger_profile_photo,
              owner.username AS owner_username,
              owner.profile_photo AS owner_profile_photo,
              exchanges.exchange_result,
              credit_points.credited_at,  -- ดึงเวลาที่บันทึกคะแนนเครดิต
              discredit_points.created_at AS discredited_at,  -- ดึงเวลาที่บันทึกคะแนนดิสเครดิต
              discredit_points.reason AS discredit_reason  -- ดึงเหตุผลของคะแนนดิสเครดิต
          FROM exchanges
          JOIN items ON exchanges.item_id = items.id
          JOIN items AS selected_items ON exchanges.selected_item_id = selected_items.id
          JOIN users AS exchanger ON exchanges.exchanger_id = exchanger.id
          JOIN users AS owner ON exchanges.owner_id = owner.id
          LEFT JOIN credit_points ON credit_points.exchange_id = exchanges.id  -- JOIN กับ credit_points
          LEFT JOIN discredit_points ON discredit_points.exchange_id = exchanges.id  -- JOIN กับ discredit_points
          WHERE exchanges.id = $1
      `, [exchangeId]);

      if (result.rows.length > 0) {
          res.json(result.rows[0]);
      } else {
          res.status(404).json({ error: "Exchange not found" });
      }
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Server error" });
  }
});






// Mark swap as completed ยังไม่ได้ใช้
app.put('/swaps/:swapId/complete', async (req, res) => {
  const { swapId } = req.params;

  try {
    const result = await pool.query(
      `UPDATE swaps SET status = 'Completed' WHERE id = $1 RETURNING *`, 
      [swapId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Swap not found' });
    }

    return res.status(200).json({ success: true, message: 'Swap marked as completed' });
  } catch (err) {
    console.error('Error marking swap as completed', err.stack);
    return res.status(500).json({ success: false, message: 'Error marking swap as completed' });
  }
});



// API สำหรับดึงสินค้าของผู้ใช้
app.get('/user-items/:userId', async (req, res) => {
  const userId = req.params.userId;

  try {
    // ดึงข้อมูลสินค้ารวมถึงฟิลด์ is_locked และตรวจสอบให้เลือกเฉพาะที่ is_locked เป็น false
    const result = await pool.query('SELECT id, item_name, item_price, item_photo, is_locked FROM items WHERE user_id = $1 AND is_locked = false AND is_deleted = FALSE', [userId]);

    // ตรวจสอบว่าพบสินค้าหรือไม่
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'ไม่พบสินค้าที่ยังไม่ได้ถูกล็อกสำหรับผู้ใช้นี้.' });
    }

    // ส่งคืนรายการสินค้ามาเป็นผลลัพธ์
    return res.json(result.rows);
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการดึงข้อมูลสินค้าของผู้ใช้:', error);
    return res.status(500).json({ message: 'ข้อผิดพลาดภายในเซิร์ฟเวอร์' });
  }
});



// ดึงการแจ้งเตือนของผู้ใช้
app.get('/notifications/:userId', async (req, res) => {
  const { userId } = req.params;

  console.log('Fetching notifications for userId:', userId); 

  try {
    const result = await pool.query(
      `SELECT 
        n.id,
        n.exchanger_id, 
        n.user_id,
        n.message,
        n.created_at,
        n.read,
        u.profile_photo AS exchanger_profile_photo, -- ดึงรูปโปรไฟล์ของผู้ขอแลก
        i.item_photo AS item_photo -- ดึงรูปภาพสินค้า
      FROM notifications n 
      LEFT JOIN exchanges e ON n.exchanger_id = e.id -- เชื่อมโยงกับ exchanges
      LEFT JOIN users u ON e.exchanger_id = u.id -- ดึงข้อมูลรูปโปรไฟล์จาก users โดยใช้ exchanger_id
      LEFT JOIN items i ON e.item_id = i.id -- เชื่อมโยงกับ items เพื่อดึงรูปภาพสินค้า
      WHERE n.user_id = $1
      ORDER BY n.created_at DESC`, 
      [userId]
    );

    console.log('Result:', result.rows); // Debugging

    if (result.rows.length === 0) {
      return res.status(200).json({ success: true, notifications: [], message: 'No notifications found' });
    }

    return res.status(200).json({ success: true, notifications: result.rows });
  } catch (err) {
    console.error('Error fetching notifications', err.stack);
    return res.status(500).json({ success: false, message: 'Error fetching notifications' });
  }
});



app.get('/notifications/id/:id', async (req, res) => {
  const { id } = req.params;

  console.log('Fetching notification for id:', id); // Debugging

  try {
      // Query ข้อมูล notification พร้อมกับข้อมูลจากตาราง users, exchanges และ items
      const result = await pool.query(
        `SELECT 
          n.id,
          n.exchanger_id, 
          n.user_id,
          n.message,
          n.created_at,
          n.read,
          e.id AS e_id,
          e.owner_id AS exchange_owner_id,
          e.exchanger_id AS exchanger_u_id,
          u2.username AS exchanger_username,  
          u2.profile_photo AS exchanger_profile_photo,  
          u3.username AS owner_username,  
          u3.profile_photo AS owner_profile_photo, 
          e.item_id,  
          e.selected_item_id,  
          e.status, 
          i.id AS selected_item_id,  
          i.item_name AS selected_item_name,  
          i.item_photo AS selected_item_photo,  
          i.item_price AS selected_item_price 
        FROM notifications n 
        JOIN users u ON n.user_id = u.id 
        LEFT JOIN exchanges e ON n.exchanger_id = e.id  
        LEFT JOIN users u2 ON e.exchanger_id = u2.id  
        LEFT JOIN users u3 ON e.owner_id = u3.id  
        LEFT JOIN items i ON e.selected_item_id = i.id  
        WHERE n.id = $1`, [id]);

      console.log('Resultdd:', result.rows);

      if (result.rows.length === 0) {
          return res.status(200).json({ success: true, notification: null, message: 'No notification found' });
      }

      // ตรวจสอบว่า user_id ใน notification เป็นเจ้าของสินค้าจาก exchanges
      const notification = result.rows[0];
      const isOwner = notification.user_id === notification.exchange_owner_id;
      console.log('Is Owner:', isOwner); // Debugging

      // Add isOwner to the notification object
      notification.isOwner = isOwner;

      // ดึง selected_item_id ที่ผู้ใช้เลือกก่อนทำการแลก
      const selectedItemId = notification.selected_item_id;

      return res.status(200).json({ 
          success: true, 
          notification: notification, // Return the modified notification object
          isOwner: isOwner,
          selectedItemId: selectedItemId, // Return selected_item_id
          exchangerId: notification.exchanger_u_id,
          e_id: notification.e_id
        });
      
  } catch (err) {
      console.error('Error fetching notification', err.stack);
      return res.status(500).json({ success: false, message: 'Error fetching notification' });
  }
});




app.get('/items/:id', async (req, res) => {
  const itemId = req.params.id; // ดึง ID ของสินค้า
  try {
      const result = await pool.query('SELECT * FROM items WHERE id = $1', [itemId]); // คำสั่ง SQL เพื่อนำข้อมูลสินค้าตาม ID
      if (result.rows.length > 0) { // ตรวจสอบว่ามีสินค้าที่ตรงตาม ID หรือไม่
          res.json({ success: true, item: result.rows[0] }); // ส่งข้อมูลสินค้ากลับไปยัง client
      } else {
          res.status(404).json({ success: false, message: 'Item not found' }); // ส่งข้อความเมื่อไม่พบสินค้า
      }
  } catch (error) {
      console.error('Error fetching item:', error); // แสดงข้อผิดพลาดใน console
      res.status(500).json({ success: false, message: 'Error fetching item' }); // ส่งข้อความเมื่อเกิดข้อผิดพลาดในการดึงข้อมูล
  }
});



app.get('/exchangedItems/:exchangerId', async (req, res) => {
  const { exchangerId } = req.params;
  console.log('ex:', req.params);

  try {
    const result = await pool.query(`
      SELECT 
        e.item_id, 
        i.id AS item_id,
        i.item_name, 
        i.item_photo,
        i.item_price,
        i.item_type,
        i.item_description
      FROM exchanges e 
      JOIN items i ON e.item_id = i.id  
      WHERE e.id = $1`, [exchangerId]);

    console.log('Resulttt:', result.rows);

    if (result.rows.length === 0) {
      return res.status(200).json({ success: true, items: [] });
    }

    return res.status(200).json({ success: true, items: result.rows });
  } catch (err) {
    console.error('Error fetching exchanged items', err.stack);
    return res.status(500).json({ success: false, message: 'Error fetching exchanged items' });
  }
});


//ทำเครื่องหมายว่าอ่านแล้ว
app.put('/notifications/:id/read', async (req, res) => {
  const { id } = req.params;

  try {
      const result = await pool.query('UPDATE notifications SET read = TRUE WHERE id = $1 RETURNING *', [id]);

      // ตรวจสอบว่ามีการอัปเดตข้อมูลหรือไม่
      if (result.rowCount === 0) {
          return res.status(404).json({ success: false, message: 'Notification not found' });
      }

      return res.status(200).json({ success: true, message: 'Notification marked as read' });
  } catch (err) {
      console.error('Error updating notification', err.stack);
      return res.status(500).json({ success: false, message: 'Error updating notification' });
  }
});


//การแจ้งเตือนที่ยังไม่ได้อ่าน
app.get('/notifications/unread-count/:user_id', async (req, res) => {
  const { user_id } = req.params;

  try {
    const result = await pool.query(
      'SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND read = FALSE',
      [user_id]
    );

    const unreadCount = result.rows[0].count; // ดึงค่าจากผลลัพธ์ query

    return res.status(200).json({
      success: true,
      unreadCount: parseInt(unreadCount, 10), // แปลงเป็นจำนวนเต็ม
    });
  } catch (err) {
    console.error('Error fetching unread notifications count', err.stack);
    return res.status(500).json({
      success: false,
      message: 'Error fetching unread notifications count',
    });
  }
});



//การส่งข้อความ
app.get('/users/:id', async (req, res) => {
  const userId = req.params.id; // ดึง id จาก parameters

  try {
    const result = await pool.query('SELECT username, firstname, lastname, profile_photo FROM users WHERE id = $1', [userId]);
    if (result.rows.length > 0) {
      res.status(200).json(result.rows[0]); // ส่งข้อมูลผู้ใช้กลับ
    } else {
      res.status(404).json({ error: 'User not found' }); // ถ้าไม่พบผู้ใช้
    }
  } catch (err) {
    console.error('Error fetching user:', err.stack);
    res.status(500).json({ error: err.message }); // จัดการข้อผิดพลาด
  }
});

app.post('/send-mes', upload.single('image'), async (req, res) => {
  console.log('Received fields:', req.body);
  console.log('Received file:', req.file);

  const { sender_id, receiver_id, message, time } = req.body;
  const image_path = req.file ? req.file.path : null;

  try {

    const result = await pool.query(
      `INSERT INTO message (sender_id, receiver_id, message, time, image_path) 
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [sender_id, receiver_id, message, time, image_path]
    );

    const messageId = result.rows[0].id;

    
    
    res.status(201).json({ success: true, messageId });
  } catch (err) {
    console.error('Error sending message:', err.stack);
    res.status(500).json({ error: err.message });
  }
});

app.get('/mes', async (req, res) => {
  const { sender_id, receiver_id } = req.query;

  try {
    
    const result = await pool.query(
      `SELECT id, sender_id, receiver_id, message, time, image_path
       FROM message 
       WHERE (sender_id = $1 AND receiver_id = $2) 
          OR (sender_id = $2 AND receiver_id = $1) 
       ORDER BY time ASC`,
      [sender_id, receiver_id]
    );

   
    const usersResult = await pool.query(
      `SELECT id, username, firstname, lastname, profile_photo 
       FROM users 
       WHERE id = $1`,
      [receiver_id]
    );

    const receiverUser = usersResult.rows[0] || {};

  
    const messages = result.rows.map(row => {
      const profileImageUrl = receiverUser.profile_photo 
        ? `/uploads/${path.basename(receiverUser.profile_photo)}` 
        : null;

      return {
        id: row.id,
        sender_id: row.sender_id,
        receiver_id: row.receiver_id,
        message: row.message,
        time: row.time,
        image_path: row.image_path 
          ? `/uploads/${path.basename(row.image_path)}` 
          : null,
        profile_image_url: profileImageUrl,  
        receiver_username: receiverUser .username || '',
        receiver_firstname: receiverUser.firstname || '',
        receiver_lastname: receiverUser.lastname || ''
      };
    });

 
    res.status(200).json({ messages });
  } catch (err) {
    console.error('Error fetching messages:', err.stack);
    res.status(500).json({ error: err.message });
  }
});

app.get('/chat-history/:userId', async (req, res) => {
  const userId = req.params.userId;

  try {
    // Query เพื่อดึง contact IDs, usernames, profile images, และข้อความล่าสุดหรือ "Send Photo" ถ้าเป็นรูปภาพ
    const result = await pool.query(
      `SELECT DISTINCT ON (contact_id)
         CASE WHEN sender_id = $1 THEN receiver_id ELSE sender_id END AS contact_id,
         u.username,
         u.profile_photo,
         CASE 
           WHEN m.image_path IS NOT NULL THEN 'Send Photo'
           ELSE m.message 
         END AS last_message
       FROM message m
       JOIN users u ON (CASE WHEN sender_id = $1 THEN receiver_id ELSE sender_id END = u.id)
       WHERE sender_id = $1 OR receiver_id = $1
       ORDER BY contact_id, m.time DESC`,
      [userId]
    );

    // สร้างอาร์เรย์ของ chat history
    const chatHistory = result.rows.map(row => ({
      contact_id: row.contact_id,
      username: row.username,
      profile_photo: row.profile_photo,
      last_message: row.last_message,
    }));

    res.status(200).json({ chatHistory });
  } catch (err) {
    console.error('Error fetching chat history:', err.stack);
    res.status(500).json({ error: err.message });
  }
});



//คะแนนเครดิตหรือดิสเครดิตหลังจากการแลกเปลี่ยนสำเร็จหรือถูกยกเลิก
// API ยืนยันการรับสินค้า
app.post('/confirm/:exchangeId', async (req, res) => { 
  const exchangeId = req.params.exchangeId;
  const { userId } = req.body;

  try {
      const exchangeResult = await pool.query('SELECT * FROM exchanges WHERE id = $1', [exchangeId]);
      if (exchangeResult.rows.length === 0) {
          return res.status(404).send("Exchange not found");
      }

      const exchange = exchangeResult.rows[0];

      // ตรวจสอบว่าผู้ใช้ที่ยืนยันเป็นเจ้าของหรือผู้แลกเปลี่ยน
      const isOwner = exchange.owner_id === userId;
      const isExchanger = exchange.exchanger_id === userId;
      const otherPartyId = isOwner ? exchange.exchanger_id : exchange.owner_id; // เก็บ ID ของผู้ที่ยังไม่กดยืนยัน

      // อัปเดตเวลายืนยันการรับสินค้าสำหรับผู้ที่กดยืนยัน
      if (isOwner) {
          const now = new Date();
          await pool.query(
              `UPDATE exchanges 
               SET owner_confirmed_item_at = $1 
               WHERE id = $2`,
              [now, exchangeId]
          );
          exchange.owner_confirmed_item_at = now; // อัปเดตค่าในตัวแปร exchange
      } else if (isExchanger) {
          const now = new Date();
          await pool.query(
              `UPDATE exchanges 
               SET exchanger_confirmed_item_at = $1 
               WHERE id = $2`,
              [now, exchangeId]
          );
          exchange.exchanger_confirmed_item_at = now; // อัปเดตค่าในตัวแปร exchange
      } else {
          return res.status(403).send("User not authorized to confirm this exchange");
      }

      // เช็คว่าทั้งสองฝ่ายยืนยันแล้วหรือยัง
      if (exchange.owner_confirmed_item_at && exchange.exchanger_confirmed_item_at) {
          // บันทึกผลการแลกเปลี่ยน
          const result = 'completed'; // ตั้งค่าผลการแลกเปลี่ยนเป็น completed
          await pool.query(
              `UPDATE exchanges 
               SET exchange_result = $1
               WHERE id = $2`,
              [result, exchangeId]
          );

          // เพิ่มคะแนนเครดิตให้กับผู้ใช้ทั้งสอง
          const now = new Date();
          const creditUpdateResult = await pool.query(
              `INSERT INTO credit_points (user_id, exchange_id, points, credited_at) 
               VALUES ($1, $2, $3, $4), ($5, $6, $7, $8) 
               ON CONFLICT (user_id, exchange_id) DO UPDATE 
               SET points = credit_points.points + 1, credited_at = $9`,
              [exchange.owner_id, exchangeId, 1, now, exchange.exchanger_id, exchangeId, 1, now, now]
          );

          if (creditUpdateResult.rowCount > 0) {
              return res.send("Both parties confirmed. Credit updated and exchange recorded.");
          } else {
              console.error(`Failed to update credit points for users: ${exchange.owner_id}, ${exchange.exchanger_id}`);
              return res.status(500).send("Failed to update credit points. No rows affected.");
          }
      }

      // ส่งการแจ้งเตือนไปยังผู้ใช้ที่ยังไม่กดยืนยัน
      const notificationMessage = "กรุณากดยืนยันรับสินค้า";
      await sendNotification(otherPartyId, notificationMessage);

      return res.send("Confirmation successful, waiting for the other party's confirmation.");

  } catch (error) {
      console.error(`Error occurred: ${error.message}`);
      return res.status(500).json({ message: 'Internal Server Error', error: error.message });
  }
});



// ฟังก์ชันส่งการแจ้งเตือน
async function sendNotification(userId, message) {
    try {
        // บันทึกการแจ้งเตือนลงในฐานข้อมูล
        await pool.query(
            `INSERT INTO notifications (user_id, message, created_at, read) 
             VALUES ($1, $2, NOW(), FALSE)`,
            [userId, message]
        );
        console.log(`Notification sent to user ${userId}: ${message}`);
    } catch (error) {
        console.error(`Error sending notification to user ${userId}: ${error.message}`);
    }
}


// API ยกเลิกการแลกเปลี่ยน
app.post('/cancel/:exchangeId', async (req, res) => {
  const exchangeId = req.params.exchangeId;
  const { userId, reason } = req.body;

  try {
    const exchangeResult = await pool.query('SELECT * FROM exchanges WHERE id = $1', [exchangeId]);
    if (exchangeResult.rows.length === 0) {
      return res.status(404).send("Exchange not found");
    }

    const exchange = exchangeResult.rows[0];
    const { owner_id, exchanger_id, item_id: owner_item_id, selected_item_id: exchanger_item_id } = exchange; 

    if (owner_id === userId || exchanger_id === userId) {
      // บันทึกเหตุผลการยกเลิกและอัปเดตสถานะ
      await pool.query(
        `UPDATE exchanges 
         SET cancellation_reason = $1, cancelled_by = $2, exchange_result = 'cancelled' 
         WHERE id = $3`,
        [reason, userId, exchangeId]
      );

      // ปลดล็อคสินค้า
      await pool.query(
        `UPDATE items 
         SET is_locked = false 
         WHERE id = $1 OR id = $2`,
        [owner_item_id, exchanger_item_id]
      );

      const userIds = [owner_id, exchanger_id];

      for (const id of userIds) {
        // สร้างรายการใหม่สำหรับดิสเครดิตในทุกการยกเลิก
        await pool.query(
          `INSERT INTO discredit_points (user_id, points, reason, exchange_id) 
           VALUES ($1, $2, $3, $4)`,
          [id, 1, reason, exchangeId] 
        );
      }

      return res.send("Exchange cancelled, both items unlocked, and discredit points updated for both users.");
    } else {
      return res.status(403).send("User not authorized to cancel this exchange");
    }

  } catch (error) {
    console.error(`Error occurred: ${error.message}`);
    return res.status(500).send(error.message);
  }
});


// API ตรวจสอบสถานะการยืนยัน
app.get('/exchange_status/:exchangeId', async (req, res) => {
  const { exchangeId } = req.params;

  console.log('Fetching exchange status for exchangeId:', exchangeId); 

  try {
    const result = await pool.query(
      `SELECT 
        id,
        exchanger_id,
        owner_id,
        item_id,
        status,
        created_at,
        selected_item_id,
        owner_confirmed_at,
        exchanger_confirmed_item_at,
        owner_confirmed_item_at,
        cancellation_reason,
        cancelled_by,
        exchange_result -- เพิ่มคอลัมน์นี้เข้าไป
      FROM exchanges
      WHERE id = $1`, 
      [exchangeId]
    );

    console.log('Result:', result.rows); 

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Exchange not found' });
    }

    const exchange = result.rows[0];

    return res.status(200).json({
      success: true,
      ownerConfirmed: !!exchange.owner_confirmed_item_at,
      exchangerConfirmed: !!exchange.exchanger_confirmed_item_at,
      exchangeResult: exchange.exchange_result, 
      exchangeDetails: exchange,
    });
  } catch (err) {
    console.error('Error fetching exchange status', err.stack);
    return res.status(500).json({ success: false, message: 'Error fetching exchange status' });
  }
});

// API สำหรับดึงคะแนนเครดิต พร้อมข้อมูลการแลกเปลี่ยน
app.get('/credit_points/:userId', async (req, res) => {
  const userId = req.params.userId;

  try {
    const query = `
      SELECT cp.user_id, cp.points, e.id AS exchange_id, e.exchange_result, i.item_name, i.item_photo
      FROM credit_points cp
      JOIN exchanges e ON cp.exchange_id = e.id -- ใช้ exchange_id ในการเชื่อมต่อ
      JOIN items i ON e.item_id = i.id
      WHERE cp.user_id = $1 AND e.exchange_result = 'completed' -- เงื่อนไขสำหรับการแลกเปลี่ยนที่สำเร็จ
    `;
    const values = [userId];

    const result = await pool.query(query, values);
    console.log(result.rows);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'ไม่มีคะแนนเครดิตในขณะนี้' });
    }

    return res.json(result.rows);
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการดึงข้อมูลคะแนนเครดิต:', error);
    return res.status(500).json({ message: 'ข้อผิดพลาดภายในเซิร์ฟเวอร์' });
  }
});

// API สำหรับดึงเหตุผลของคะแนนดิสเครดิต พร้อมข้อมูลการแลกเปลี่ยน
app.get('/discredit_points/:userId', async (req, res) => {
  const userId = req.params.userId;

  try {
    const query = `
      SELECT dp.user_id, dp.points, dp.reason, dp.created_at, e.id AS exchange_id, e.exchange_result, i.item_name, i.item_photo
      FROM discredit_points dp
      JOIN exchanges e ON dp.exchange_id = e.id -- ใช้ exchange_id ในการเชื่อมต่อ
      JOIN items i ON e.item_id = i.id
      WHERE dp.user_id = $1 AND e.exchange_result = 'cancelled' -- เงื่อนไขสำหรับการแลกเปลี่ยนที่ถูกยกเลิก
    `;
    const values = [userId];

    const result = await pool.query(query, values);
    console.log(result.rows);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'ไม่มีคะแนนดิสเครดิตในขณะนี้' });
    }

    return res.json(result.rows);
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการดึงข้อมูลคะแนนดิสเครดิต:', error);
    return res.status(500).json({ message: 'ข้อผิดพลาดภายในเซิร์ฟเวอร์' });
  }
});





//Admin
// API สำหรับดึงข้อมูล Activity Log
app.get('/getActivityLogs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM activity_log ORDER BY activity_time DESC');
    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error fetching activity logs', err.stack);
    res.status(500).send('Error fetching activity logs');
  }
});

app.get('/getUsers', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, firstname, lastname, is_banned FROM users');
    console.log(result.rows); // ตรวจสอบข้อมูลที่ได้จากฐานข้อมูล

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'No users found' });
    }

    return res.status(200).json({ success: true, users: result.rows });
  } catch (err) {
    console.error('Error fetching users', err.stack);
    return res.status(500).json({ success: false, message: 'Error fetching users' });
  }
});

app.post('/getUserStatus', async (req, res) => {
  console.log(req.body); // บันทึกข้อมูลที่เข้ามา
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ success: false, message: 'Please provide user ID' });
  }

  try {
    const result = await pool.query('SELECT is_banned FROM users WHERE id = $1', [userId]);
    const user = result.rows[0];

    if (user) {
      console.log('User found:', user); // บันทึกข้อมูลผู้ใช้ที่ค้นพบ
      return res.status(200).json({ success: true, status: user.is_banned });
    } else {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
  } catch (err) {
    console.error('Error checking user status', err);
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


app.put('/banUser', async (req, res) => {
  const { userId, isBanned } = req.body;

  try {
    const banTime = isBanned ? new Date() : null; 
    const result = await pool.query(
      'UPDATE users SET is_banned = $1, ban_time = $2 WHERE id = $3 RETURNING *',
      [isBanned, banTime, userId]
    );

    if (result.rowCount > 0) {
      const user = result.rows[0];
      const { username, firstname, lastname } = user;

      await pool.query(
        'INSERT INTO activity_log (activity_name, user_id, details) VALUES ($1, $2, $3)',
        [
          'banUser',
          userId,
          `User ${isBanned ? 'banned' : 'unbanned'}: ${username} (${firstname} ${lastname})`
        ]
      );

      return res.status(200).json({ success: true, user: user });
    } else {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
  } catch (err) {
    console.error('Error updating ban status', err.stack);
    return res.status(500).json({ success: false, message: 'Error updating ban status' });
  }
});


// Endpoint สำหรับ admin ลบสินค้า
app.put('/adminDeleted/:itemId', async (req, res) => {
  const itemId = req.params.itemId;
  console.log(req.body)
  try {
    // ตรวจสอบว่าสินค้าอยู่ในระบบหรือไม่
    const itemResult = await pool.query('SELECT * FROM items WHERE id = $1', [itemId]);
    const item = itemResult.rows[0];

    if (!item) {
      console.log("ไม่พบสินค้าในฐานข้อมูลสำหรับ ID:", itemId); // เพิ่มล็อกเมื่อไม่พบสินค้า
      return res.status(404).json({ success: false, message: 'ไม่พบสินค้า' });
    }

    // บันทึกกิจกรรมการลบสินค้า
    try {
      await logActivity(item.user_id, 'Admin Delete Item', `Item "${item.item_name}" deleted by admin`);
    } catch (logError) {
      console.error('Failed to log activity:', logError);
    }

    // อัปเดตสถานะ is_deleted ของสินค้าในฐานข้อมูล
    const updateResult = await pool.query(
      'UPDATE items SET is_deleted = TRUE WHERE id = $1 RETURNING *;',
      [itemId]
    );

    if (updateResult.rows.length > 0) {
      console.log("ลบสินค้า:", item.item_name); // เพิ่มล็อกเมื่อสินค้าถูกลบสำเร็จ

      const notificationMessage = `แอดมินได้ลบสินค้าของคุณ "${item.item_name}"`;

      return res.status(200).json({ success: true, message: 'ลบสินค้าสำเร็จแล้ว' });
    } else {
      console.log("ไม่สามารถลบสินค้าได้ ID:", itemId); // เพิ่มล็อกเมื่อไม่สามารถลบสินค้าได้
      return res.status(500).json({ success: false, message: 'ไม่สามารถลบสินค้าได้' });
    }
  } catch (error) {
    console.error('Error deleting item:', error);
    return res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์' });
  }
});

// Route สำหรับรีพอร์ตสินค้า เมื่อจำนวนรีพอร์ตถึง threshold แล้วลบสินค้าอัตโนมัติ
app.post('/reportItem', async (req, res) => {
  const { itemId, userId, reason } = req.body;

  try {
    // เปลี่ยนจาก item_id เป็น id ตามโครงสร้างตาราง
    const itemResult = await pool.query('SELECT * FROM items WHERE id = $1', [itemId]);
    if (itemResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }

    const item = itemResult.rows[0];
    const reportData = JSON.stringify({
      item_id: item.id, // เปลี่ยนจาก item.item_id เป็น item.id
      item_name: item.item_name,
      item_type: item.item_type,
      item_price: item.item_price,
      item_photo: JSON.stringify(item.item_photo),
      user_id: item.user_id,
    });

    await pool.query(
      'INSERT INTO report (item_id, user_id, reason, report_data) VALUES ($1, $2, $3, $4)',
      [itemId, userId, reason, reportData]
    );

    const deleteThresholds = {
      "สินค้านอกเหนือจากเสื้อผ้าและเครื่องประดับ": 5,
      "สินค้าผิดกฎหมาย": 3,
      "ชื่อ/ภาพของสินค้ามีความอนาจาร": 5,
    };

    const reportCounts = await pool.query(
      'SELECT COUNT(*) AS count FROM report WHERE item_id = $1 AND reason = $2',
      [itemId, reason]
    );
    const reportCount = parseInt(reportCounts.rows[0].count, 10);

    if (reportCount >= deleteThresholds[reason]) {
      await logActivity(item.user_id, 'Auto Delete Item', 
        `Item "${item.item_name}" automatically deleted due to reaching report threshold`);

      const updateResult = await pool.query(
        'UPDATE items SET is_deleted = TRUE WHERE id = $1 RETURNING *', // เปลี่ยนจาก item_id เป็น id
        [itemId]
      );

      if (updateResult.rows.length > 0) {
        const notificationMessage = `แอดมินได้ลบสินค้าของคุณ "${item.item_name}"`;
        
        await pool.query(
          'INSERT INTO notifications (user_id, message, type, created_at) VALUES ($1, $2, $3, NOW())',
          [item.user_id, notificationMessage, 'auto_delete']
        );

        io.to(item.user_id).emit('notification', notificationMessage);
      }
    }

    res.status(201).json({ success: true, message: 'Report submitted successfully' });
  } catch (error) {
    console.error('Error reporting item:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// API สำหรับดึงข้อมูลรายงานทั้งหมด
app.get('/getReports', async (req, res) => {
  try {
    const reports = await pool.query(`
      SELECT 
        report.report_id,
        items.item_name,
        report.reason,
        reporter.username AS reporter,
        owner.username AS owner,
        report.report_date
      FROM report
      JOIN items ON report.item_id = items.id
      JOIN users AS reporter ON report.user_id = reporter.id
      JOIN users AS owner ON items.user_id = owner.id
    `);
    res.json({ success: true, reports: reports.rows });
  } catch (error) {
    console.error('Error fetching reports:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});


app.post('/logActivity', async (req, res) => {
  const { userId, activityName, details, timestamp } = req.body;

  try {
    const result = await pool.query(
      'INSERT INTO activity_log (user_id, activity_name, details, activity_time) VALUES ($1, $2, $3, $4)',
      [userId, activityName, details, timestamp]
    );

    res.status(200).send('Activity logged successfully');
  } catch (err) {
    console.error('Error logging activity', err.stack);
    res.status(500).send('Error logging activity');
  }
});



// ตั้งค่าการเชื่อมต่อของ socket.io
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  // ให้ผู้ใช้เข้าร่วมช่องด้วย userId
  socket.on('join', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined channel`);
  });

  // เมื่อมีการส่งการแจ้งเตือน
  socket.on('notification', (data) => {
    console.log('Notification received:', data);
    const { userId, message } = data; 
    socket.to(userId).emit('notification', message); 
  });

  // เมื่อผู้ใช้ยกเลิกการเชื่อมต่อ
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});


// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
