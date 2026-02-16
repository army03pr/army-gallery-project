require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const https = require('https');
const archiver = require('archiver');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

// ==========================================
// 1. ตรวจสอบ Config และ Environment
// ==========================================
if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
    console.warn("⚠️  คำเตือน: คุณยังไม่ได้ใส่ค่า Cloudinary ในไฟล์ .env (ฟังก์ชันอัปโหลดและ Stats จะทำงานไม่สมบูรณ์)");
}

const JWT_SECRET = process.env.JWT_SECRET || 'army_secret_key_1234';
const PORT = process.env.PORT || 3001;

// ==========================================
// 2. Middleware & Security
// ==========================================
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// Security Headers
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://cdn.jsdelivr.net",
                    "https://npmcdn.com",
                    "https://cdnjs.cloudflare.com"
                ],
                styleSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://fonts.googleapis.com",
                    "https://cdnjs.cloudflare.com",
                    "https://cdn.jsdelivr.net"
                ],
                imgSrc: [
                    "'self'",
                    "data:",
                    "https://res.cloudinary.com",
                    "blob:"
                ],
                fontSrc: [
                    "'self'",
                    "https://fonts.gstatic.com"
                ],
                connectSrc: ["'self'"],
            },
        },
        crossOriginResourcePolicy: false,
    })
);

// Cache Control
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

// Rate Limiting
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: "Too many requests, please try again later." });
const uploadLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: "Upload limit exceeded." });
app.use('/api/', apiLimiter);

// ==========================================
// 3. Database & Cloudinary Configuration
// ==========================================

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'army_gallery',
        allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
    },
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }
});

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 4000,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME || 'army_photo_gallery',
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true },
    multipleStatements: false,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Check DB Connection
(async () => {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Connected to Database Successfully!');
        connection.release();
    } catch (err) {
        console.error('❌ Database Connection Failed:', err.message);
    }
})();

// ==========================================
// 4. Helper Functions
// ==========================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

function adminOnly(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
}

function validateInput(data, rules) {
    for (const [field, rule] of Object.entries(rules)) {
        const value = data[field];
        if (rule.required && (!value || (typeof value === 'string' && value.trim() === ''))) {
            return { valid: false, message: `${field} is required` };
        }
        if (rule.minLength && value.length < rule.minLength) {
            return { valid: false, message: `${field} must be at least ${rule.minLength} characters` };
        }
        if (rule.maxLength && value.length > rule.maxLength) {
            return { valid: false, message: `${field} must be at most ${rule.maxLength} characters` };
        }
    }
    return { valid: true };
}

async function logAction(userId, username, action, details, req) {
    try {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown';
        await pool.query(
            'INSERT INTO Logs (user_id, username, action, details, ip_address) VALUES (?, ?, ?, ?, ?)',
            [userId, username, action, details, ip]
        );
    } catch (err) {
        console.error('Log Error:', err.message);
    }
}

function getPublicIdFromUrl(url) {
    try {
        const parts = url.split('/');
        const filename = parts.pop();
        const folder = parts.pop();
        return folder + '/' + filename.split('.')[0];
    } catch (e) {
        return null;
    }
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0 || isNaN(bytes)) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 🔥 วิธีที่ 1: ดึงข้อมูลจริงจาก Cloudinary API (Real Storage Usage) + Auto-detect Plan
async function getCloudinaryUsage() {
    try {
        console.log('📊 Fetching Cloudinary Real Storage Usage...');
        
        // 🔥 ดึงข้อมูล Plan จาก Cloudinary API
        const usageData = await cloudinary.api.usage();
        console.log('Raw Usage Data:', JSON.stringify(usageData, null, 2));
        
        // ดึงรายการไฟล์ทั้งหมดจาก Cloudinary
        let allResources = [];
        let nextCursor = null;
        let apiCallCount = 0;
        
        do {
            apiCallCount++;
            console.log(`   API Call #${apiCallCount}${nextCursor ? ' (pagination)' : ''}`);
            
            const result = await cloudinary.api.resources({
                type: 'upload',
                prefix: 'army_gallery/',
                max_results: 500,
                next_cursor: nextCursor
            });
            
            if (result.resources && result.resources.length > 0) {
                allResources = allResources.concat(result.resources);
                console.log(`   ✓ Fetched ${result.resources.length} files (Total: ${allResources.length})`);
            }
            
            nextCursor = result.next_cursor;
            
            // ป้องกันการวนลูปไม่รู้จบ (สูงสุด 20 หน้า = 10,000 ไฟล์)
            if (apiCallCount >= 20) {
                console.warn('⚠️  Reached pagination limit (20 pages)');
                break;
            }
            
        } while (nextCursor);

        // คำนวณขนาดจริง
        let totalBytes = 0;
        let fileCount = 0;

        allResources.forEach(resource => {
            const fileSize = resource.bytes || 0;
            totalBytes += fileSize;
            fileCount++;
        });

        console.log(`📦 Summary: ${fileCount} files, ${formatBytes(totalBytes)}`);

        // 🔥 ดึง Limit จาก API อัตโนมัติ (รองรับทุก Plan)
        let limit = 26843545600; // Default: 25 GB for Free Plan
        let planName = 'Free';
        
        // ลอง 1: ดึงจาก storage.limit
        if (usageData.storage && typeof usageData.storage.limit === 'number' && usageData.storage.limit > 0) {
            limit = usageData.storage.limit;
            planName = usageData.plan || 'Paid';
            console.log(`✅ Found storage.limit from API: ${formatBytes(limit)} (Plan: ${planName})`);
        }
        // ลอง 2: ดึงจาก credits.limit
        else if (usageData.credits && typeof usageData.credits.limit === 'number' && usageData.credits.limit > 0) {
            const creditsLimit = usageData.credits.limit;
            
            // ถ้าเป็นตัวเลขเล็ก (< 10000) น่าจะเป็น Credits (GB)
            if (creditsLimit < 10000) {
                limit = creditsLimit * 1024 * 1024 * 1024; // Convert GB to Bytes
                console.log(`✅ Converted credits.limit ${creditsLimit} GB to ${formatBytes(limit)}`);
            } else {
                limit = creditsLimit; // ถ้าเป็นตัวเลขใหญ่ น่าจะเป็น Bytes แล้ว
                console.log(`✅ Using credits.limit as bytes: ${formatBytes(limit)}`);
            }
            
            planName = usageData.plan || 'Paid';
            console.log(`✅ Plan: ${planName}`);
        }
        // ลอง 3: ดึงจาก bandwidth.limit
        else if (usageData.bandwidth && typeof usageData.bandwidth.limit === 'number' && usageData.bandwidth.limit > 0) {
            limit = usageData.bandwidth.limit;
            planName = usageData.plan || 'Paid';
            console.log(`✅ Found bandwidth.limit from API: ${formatBytes(limit)} (Plan: ${planName})`);
        }
        // ลอง 4: ดึงจาก transformations.limit
        else if (usageData.transformations && typeof usageData.transformations.limit === 'number' && usageData.transformations.limit > 0) {
            limit = usageData.transformations.limit;
            planName = usageData.plan || 'Paid';
            console.log(`✅ Found transformations.limit from API: ${formatBytes(limit)} (Plan: ${planName})`);
        }
        // ไม่เจอ: ใช้ค่า Default
        else {
            console.log(`⚠️  No limit found in API response, using default: 25 GB (Free Plan)`);
            
            // ลองเช็คว่ามี plan name บอกไว้หรือไม่
            if (usageData.plan && usageData.plan.toLowerCase() !== 'free') {
                planName = usageData.plan;
                
                // ประมาณการ limit ตาม plan name
                switch (planName.toLowerCase()) {
                    case 'plus':
                        limit = 268435456000; // 250 GB
                        console.log(`🔍 Detected Plus plan, estimated limit: ${formatBytes(limit)}`);
                        break;
                    case 'advanced':
                        limit = 1099511627776; // 1 TB
                        console.log(`🔍 Detected Advanced plan, estimated limit: ${formatBytes(limit)}`);
                        break;
                    default:
                        console.log(`🔍 Detected ${planName} plan, using Free plan default`);
                }
            }
        }

        const percent = limit > 0 ? parseFloat(((totalBytes / limit) * 100).toFixed(4)) : 0;

        const response = {
            used_bytes: totalBytes,
            used_readable: formatBytes(totalBytes),
            limit_bytes: limit,
            limit_readable: formatBytes(limit),
            usage_percent: percent,
            plan: planName,
            file_count: fileCount
        };

        console.log('✅ Real Storage Usage:', JSON.stringify(response, null, 2));
        return response;

    } catch (e) {
        console.error("❌ Cloudinary Usage API Error:", e.message);
        console.error("Stack:", e.stack);
        
        // Return ค่า Default
        const fallbackResponse = {
            used_bytes: 0,
            used_readable: '0 Bytes',
            limit_bytes: 26843545600,
            limit_readable: '25 GB',
            usage_percent: 0,
            plan: 'Free',
            file_count: 0,
            error: e.message
        };
        
        console.log('📦 Returning Fallback Response');
        return fallbackResponse;
    }
}

// ==========================================
// 5. API Routes
// ==========================================

// --- Public Routes ---

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/public/photos', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
    const offset = (page - 1) * limit;

    try {
        const [results] = await pool.query(`
            SELECT Photos.*, Categories.name as activity_name 
            FROM Photos 
            LEFT JOIN Categories ON Photos.category_id = Categories.category_id 
            WHERE status='approved' AND is_deleted=0 
            ORDER BY upload_date DESC LIMIT ? OFFSET ?`,
            [limit, offset]
        );

        const photos = results.map(p => ({
            id: p.photo_id,
            url: p.file_path,
            original_url: p.file_path,
            filename: p.file_name,
            activity: p.activity_name || 'กิจกรรมทั่วไป',
            date: p.upload_date
        }));
        res.json(photos);
    } catch (err) {
        console.error('Public photos error:', err);
        res.status(500).json({ error: 'Failed to fetch public photos' });
    }
});

app.get('/public/categories', async (req, res) => {
    try {
        const [results] = await pool.query('SELECT * FROM Categories ORDER BY created_at DESC');
        res.json(results);
    } catch (err) {
        console.error('Public categories error:', err);
        res.status(500).json({ error: 'Failed to fetch categories' });
    }
});

// --- Authentication ---

app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    const validation = validateInput(req.body, {
        username: { required: true, minLength: 8, maxLength: 50 },
        password: { required: true, minLength: 8, maxLength: 100 }
    });

    if (!validation.valid) return res.status(400).json({ message: validation.message });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO Users (username, password, role) VALUES (?, ?, ?)',
            [username, hashedPassword, role || 'uploader']
        );
        res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ!' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Username already exists' });
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const validation = validateInput(req.body, {
        username: { required: true },
        password: { required: true }
    });

    if (!validation.valid) return res.status(400).json({ message: validation.message });

    try {
        const [users] = await pool.query('SELECT * FROM Users WHERE username = ?', [username]);
        if (users.length === 0) return res.status(404).json({ message: 'ไม่พบผู้ใช้' });

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });

        const token = jwt.sign({ id: user.user_id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
        await logAction(user.user_id, user.username, 'Login', 'เข้าสู่ระบบสำเร็จ', req);

        res.json({
            message: 'เข้าสู่ระบบสำเร็จ',
            token,
            user: { user_id: user.user_id, username: user.username, role: user.role }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// --- Upload ---

app.post('/upload', uploadLimiter, authenticateToken, upload.array('photos', 30), async (req, res) => {
    if (!req.files || req.files.length === 0) return res.status(400).json({ message: 'กรุณาเลือกรูปภาพ' });

    const uploader_id = req.user.id;
    const category_name = req.body.category_name?.trim();

    if (!category_name) return res.status(400).json({ message: 'กรุณาระบุชื่อกิจกรรม' });

    try {
        const [users] = await pool.query('SELECT username FROM Users WHERE user_id = ?', [uploader_id]);
        const uploaderName = users[0] ? users[0].username : 'Unknown';

        let catId;
        const [cats] = await pool.query('SELECT category_id FROM Categories WHERE name = ?', [category_name]);
        if (cats.length > 0) {
            catId = cats[0].category_id;
        } else {
            const [result] = await pool.query('INSERT INTO Categories (name) VALUES (?)', [category_name]);
            catId = result.insertId;
        }

        const values = req.files.map(file => [
            file.originalname,
            file.path,
            file.path,
            uploader_id,
            catId,
            'approved'
        ]);

        await pool.query('INSERT INTO Photos (file_name, file_path, thumbnail_path, uploader_id, category_id, status) VALUES ?', [values]);
        await logAction(uploader_id, uploaderName, 'Upload', `อัปโหลด ${req.files.length} รูป (Auto Approve)`, req);

        res.status(201).json({ message: `อัปโหลดสำเร็จ ${req.files.length} รูป` });
    } catch (err) {
        console.error('Upload error:', err);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// --- Photos Management (PRIVATE API) ---

app.get('/photos', authenticateToken, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 1000);
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const category = req.query.category || '';

    let sql = `
        SELECT Photos.*, Users.username, Categories.name AS activity_name 
        FROM Photos 
        LEFT JOIN Users ON Photos.uploader_id = Users.user_id
        LEFT JOIN Categories ON Photos.category_id = Categories.category_id
        WHERE Photos.status = 'approved' AND Photos.is_deleted = 0 
    `;

    const params = [];

    if (req.user.role !== 'admin') {
        sql += ` AND Photos.uploader_id = ?`;
        params.push(req.user.id);
    }

    if (search) {
        sql += ` AND (Photos.file_name LIKE ? OR Users.username LIKE ?)`;
        params.push(`%${search}%`, `%${search}%`);
    }

    if (category) {
        sql += ` AND Categories.name = ?`;
        params.push(category);
    }

    sql += ` ORDER BY Photos.upload_date DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    try {
        const [results] = await pool.query(sql, params);
        const photos = results.map(photo => ({
            id: photo.photo_id,
            url: photo.file_path,
            original_url: photo.file_path,
            filename: photo.file_name,
            uploader: photo.username,
            activity: photo.activity_name || 'กิจกรรมทั่วไป',
            date: photo.upload_date
        }));
        res.json(photos);
    } catch (err) {
        console.error('Get photos error:', err);
        res.status(500).json({ error: 'Failed to fetch photos' });
    }
});

app.put('/photos/:id/details', authenticateToken, adminOnly, async (req, res) => {
    const { category_name, custom_date } = req.body;
    const photoId = req.params.id;

    if (!category_name || !custom_date) return res.status(400).json({ message: 'ข้อมูลไม่ครบถ้วน' });

    try {
        let catId;
        const [cats] = await pool.query('SELECT category_id FROM Categories WHERE name = ?', [category_name]);
        if (cats.length > 0) {
            catId = cats[0].category_id;
        } else {
            const [result] = await pool.query('INSERT INTO Categories (name) VALUES (?)', [category_name]);
            catId = result.insertId;
        }

        await pool.query('UPDATE Photos SET category_id = ?, upload_date = ? WHERE photo_id = ?', [catId, custom_date, photoId]);

        const [users] = await pool.query('SELECT username FROM Users WHERE user_id = ?', [req.user.id]);
        const actor = users[0] ? users[0].username : 'Admin';
        await logAction(req.user.id, actor, 'Edit', `แก้ไขข้อมูลรูป ID: ${photoId}`, req);

        res.json({ message: 'แก้ไขข้อมูลเรียบร้อย' });
    } catch (err) {
        console.error('Edit details error:', err);
        res.status(500).json({ error: 'แก้ไขข้อมูลล้มเหลว' });
    }
});

app.put('/photos/:id/rename', authenticateToken, adminOnly, async (req, res) => {
    const newName = req.body.new_name?.trim();
    if (!newName) return res.status(400).json({ message: 'New name required' });
    try {
        await pool.query('UPDATE Photos SET file_name = ? WHERE photo_id = ?', [newName, req.params.id]);

        const [users] = await pool.query('SELECT username FROM Users WHERE user_id = ?', [req.user.id]);
        const actor = users[0] ? users[0].username : 'Admin';
        await logAction(req.user.id, actor, 'Rename', `เปลี่ยนชื่อรูป ID: ${req.params.id} เป็น "${newName}"`, req);

        res.json({ message: 'Renamed successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Rename failed' });
    }
});

// --- DELETE / RESTORE Operations ---

app.delete('/photos/:id/soft-delete', authenticateToken, adminOnly, async (req, res) => {
    try {
        await pool.query('UPDATE Photos SET is_deleted = 1 WHERE photo_id = ?', [req.params.id]);

        const [users] = await pool.query('SELECT username FROM Users WHERE user_id = ?', [req.user.id]);
        const actor = users[0] ? users[0].username : 'Admin';
        await logAction(req.user.id, actor, 'Delete', `ลบรูป ID: ${req.params.id} ลงถังขยะ`, req);

        res.json({ message: 'Moved to trash' });
    } catch (err) {
        res.status(500).json({ error: 'Delete failed' });
    }
});

app.post('/photos/bulk-delete', authenticateToken, adminOnly, async (req, res) => {
    const { photo_ids } = req.body;
    if (!photo_ids || !photo_ids.length) return res.status(400).json({ message: 'No photos selected' });
    try {
        await pool.query('UPDATE Photos SET is_deleted = 1 WHERE photo_id IN (?)', [photo_ids]);

        const [users] = await pool.query('SELECT username FROM Users WHERE user_id = ?', [req.user.id]);
        const actor = users[0] ? users[0].username : 'Admin';
        await logAction(req.user.id, actor, 'Bulk Delete', `ลบรูปจำนวน ${photo_ids.length} รูป ลงถังขยะ`, req);

        res.json({ message: 'Bulk deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Bulk delete failed' });
    }
});

app.get('/photos/trash', authenticateToken, adminOnly, async (req, res) => {
    try {
        const [results] = await pool.query('SELECT * FROM Photos WHERE is_deleted = 1 ORDER BY upload_date DESC');
        const photos = results.map(p => ({ id: p.photo_id, url: p.file_path, filename: p.file_name }));
        res.json(photos);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch trash' });
    }
});

app.post('/photos/trash/restore', authenticateToken, adminOnly, async (req, res) => {
    const { photo_ids } = req.body;
    if (!photo_ids || !photo_ids.length) return res.status(400).json({ message: 'No photos to restore' });
    try {
        await pool.query('UPDATE Photos SET is_deleted = 0 WHERE photo_id IN (?)', [photo_ids]);

        const [users] = await pool.query('SELECT username FROM Users WHERE user_id = ?', [req.user.id]);
        const actor = users[0] ? users[0].username : 'Admin';
        await logAction(req.user.id, actor, 'Restore', `กู้คืนรูปจำนวน ${photo_ids.length} รูป`, req);

        res.json({ message: 'Restored successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Restore failed' });
    }
});

app.delete('/photos/trash/empty', authenticateToken, adminOnly, async (req, res) => {
    const { photo_ids } = req.body;
    if (!photo_ids || !photo_ids.length) return res.status(400).json({ message: 'No photos to delete' });
    try {
        const [photos] = await pool.query('SELECT file_path FROM Photos WHERE photo_id IN (?)', [photo_ids]);
        for (const photo of photos) {
            const publicId = getPublicIdFromUrl(photo.file_path);
            if (publicId) {
                cloudinary.uploader.destroy(publicId).catch(err => console.error('Cloudinary del error:', err.message));
            }
        }
        await pool.query('DELETE FROM Photos WHERE photo_id IN (?)', [photo_ids]);

        const [users] = await pool.query('SELECT username FROM Users WHERE user_id = ?', [req.user.id]);
        const actor = users[0] ? users[0].username : 'Admin';
        await logAction(req.user.id, actor, 'Permanent Delete', `ลบรูปถาวรจำนวน ${photo_ids.length} รูป`, req);

        res.json({ message: 'Permanently deleted' });
    } catch (err) {
        console.error('Permanent delete error:', err);
        res.status(500).json({ error: 'Delete failed' });
    }
});

// --- Profile Management ---

app.put('/profile/password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });
    try {
        const [users] = await pool.query('SELECT * FROM Users WHERE user_id = ?', [req.user.id]);
        if (users.length === 0) return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        const user = users[0];
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) return res.status(400).json({ message: 'รหัสผ่านเดิมไม่ถูกต้อง' });
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE Users SET password = ? WHERE user_id = ?', [hashedPassword, req.user.id]);
        
        await logAction(req.user.id, user.username, 'Change Password', 'เปลี่ยนรหัสผ่านส่วนตัว', req);
        
        res.json({ message: 'เปลี่ยนรหัสผ่านสำเร็จ' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/profile/username', authenticateToken, async (req, res) => {
    const { newUsername } = req.body;
    if (!newUsername) return res.status(400).json({ message: 'กรุณากรอกชื่อใหม่' });
    try {
        const [users] = await pool.query('SELECT username FROM Users WHERE user_id = ?', [req.user.id]);
        const oldUsername = users[0] ? users[0].username : 'Unknown';

        await pool.query('UPDATE Users SET username = ? WHERE user_id = ?', [newUsername, req.user.id]);
        
        await logAction(req.user.id, newUsername, 'Change Username', `เปลี่ยนชื่อจาก "${oldUsername}" เป็น "${newUsername}"`, req);

        res.json({ message: 'เปลี่ยนชื่อสำเร็จ' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'ชื่อนี้มีคนใช้แล้ว' });
        res.status(500).json({ error: err.message });
    }
});

// --- Stats & Storage ---

app.get('/stats', authenticateToken, async (req, res) => {
    try {
        if (req.user.role === 'admin') {
            await pool.query('DELETE FROM Categories WHERE category_id NOT IN (SELECT DISTINCT category_id FROM Photos)');
        }

        let totalSql, trashSql, catSql;
        let params = [];

        if (req.user.role === 'admin') {
            totalSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 0';
            trashSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 1';
            catSql = 'SELECT COUNT(*) as count FROM Categories';
        } else {
            totalSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 0 AND uploader_id = ?';
            trashSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 1 AND uploader_id = ?';
            catSql = 'SELECT COUNT(*) as count FROM Categories';
            params = [req.user.id];
        }

        const [totalRes] = await pool.query(totalSql, params);
        const [trashRes] = await pool.query(trashSql, params);
        const [catRes] = await pool.query(catSql);

        res.json({
            total_photos: totalRes[0].count,
            pending_photos: 0,
            total_categories: catRes[0].count,
            trash_count: trashRes[0].count
        });
    } catch (err) {
        console.error('Stats error:', err);
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

// 🔥 Updated Storage Usage API - ใช้ Real Storage จาก Cloudinary
app.get('/storage/usage', authenticateToken, async (req, res) => {
    try {
        console.log('📊 GET /storage/usage - Starting...');
        
        const cloudinaryUsage = await getCloudinaryUsage();
        
        const [photosCount] = await pool.query('SELECT COUNT(*) as total FROM Photos WHERE is_deleted = 0');
        const [trashCount] = await pool.query('SELECT COUNT(*) as total FROM Photos WHERE is_deleted = 1');
        const [latestStats] = await pool.query(`
            SELECT c.name as category_name, COUNT(p.photo_id) as photo_count, MAX(p.upload_date) as last_update
            FROM Categories c
            LEFT JOIN Photos p ON c.category_id = p.category_id AND p.is_deleted = 0
            WHERE c.category_id IN (SELECT DISTINCT category_id FROM Photos WHERE is_deleted = 0)
            GROUP BY c.category_id, c.name
            ORDER BY last_update DESC
            LIMIT 5
        `);
        
        const response = {
            cloudinary: cloudinaryUsage,
            database: {
                active_photos: photosCount[0].total,
                trash_photos: trashCount[0].total,
                total_photos: photosCount[0].total + trashCount[0].total
            },
            latest_categories: latestStats
        };
        
        console.log('✅ Sending response:', JSON.stringify(response, null, 2));
        res.json(response);
    } catch (error) {
        console.error('❌ Storage usage error:', error);
        res.status(500).json({ error: 'Failed to get storage usage' });
    }
});

app.get('/storage/average', authenticateToken, async (req, res) => {
    try {
        const result = await cloudinary.api.resources({ type: 'upload', prefix: 'army_gallery/', max_results: 500 });
        let totalBytes = 0;
        let count = 0;

        if (result.resources && result.resources.length > 0) {
            result.resources.forEach(res => {
                totalBytes += res.bytes;
                count++;
            });
        }

        const avg = count > 0 ? totalBytes / count : 0;
        res.json({
            average_bytes: Math.round(avg),
            average_readable: formatBytes(avg),
            sample_size: count
        });
    } catch (error) {
        console.error('Average size error:', error);
        res.json({ average_readable: '0 B' });
    }
});

// --- General Data ---

app.get('/categories', authenticateToken, async (req, res) => {
    try {
        const [results] = await pool.query('SELECT * FROM Categories ORDER BY created_at DESC');
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch categories' });
    }
});

app.get('/logs', authenticateToken, adminOnly, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    try {
        const [countResult] = await pool.query('SELECT COUNT(*) as total FROM Logs');
        const totalLogs = countResult[0].total;

        const [results] = await pool.query(
            'SELECT * FROM Logs ORDER BY created_at DESC LIMIT ? OFFSET ?',
            [limit, offset]
        );

        res.json({
            data: results,
            total: totalLogs,
            totalPages: Math.ceil(totalLogs / limit),
            currentPage: page
        });
    } catch (err) {
        console.error('Logs Error:', err);
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});

// --- User Management ---

app.get('/users', authenticateToken, adminOnly, async (req, res) => {
    try {
        const [results] = await pool.query('SELECT user_id, username, role, created_at FROM Users ORDER BY created_at DESC');
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.post('/users', authenticateToken, adminOnly, async (req, res) => {
    const validation = validateInput(req.body, { username: { required: true, minLength: 8, maxLength: 50 }, password: { required: true, minLength: 8, maxLength: 100 } });
    if (!validation.valid) return res.status(400).json({ message: validation.message });
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        await pool.query('INSERT INTO Users (username, password, role) VALUES (?, ?, ?)', [req.body.username, hashedPassword, req.body.role]);
        
        await logAction(req.user.id, 'Admin', 'Create User', `สร้างผู้ใช้ใหม่: ${req.body.username}`, req);

        res.json({ message: 'User added successfully' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Username already exists' });
        res.status(500).json({ error: 'Failed to add user' });
    }
});

app.delete('/users/:id', authenticateToken, adminOnly, async (req, res) => {
    try {
        await pool.query('DELETE FROM Users WHERE user_id = ?', [req.params.id]);
        
        await logAction(req.user.id, 'Admin', 'Delete User', `ลบผู้ใช้ ID: ${req.params.id}`, req);

        res.json({ message: 'User deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.put('/users/:id/reset', authenticateToken, adminOnly, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
        await pool.query('UPDATE Users SET password = ? WHERE user_id = ?', [hashedPassword, req.params.id]);
        
        await logAction(req.user.id, 'Admin', 'Reset Password', `รีเซ็ตรหัสผ่านผู้ใช้ ID: ${req.params.id}`, req);

        res.json({ message: 'Password reset successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Password reset failed' });
    }
});

app.put('/users/:id/username', authenticateToken, adminOnly, async (req, res) => {
    try {
        await pool.query('UPDATE Users SET username = ? WHERE user_id = ?', [req.body.newUsername, req.params.id]);
        
        await logAction(req.user.id, 'Admin', 'Change Username', `เปลี่ยนชื่อผู้ใช้ ID: ${req.params.id} เป็น "${req.body.newUsername}"`, req);

        res.json({ message: 'Username changed' });
    } catch (err) {
        res.status(500).json({ error: 'Username change failed' });
    }
});

// --- Download Zip ---

app.get('/download-zip/:categoryName', async (req, res) => {
    try {
        const [cats] = await pool.query('SELECT category_id FROM Categories WHERE name = ?', [req.params.categoryName]);
        if (cats.length === 0) return res.status(404).send('Category not found');

        const [photos] = await pool.query('SELECT file_path, file_name FROM Photos WHERE category_id = ? AND status="approved" AND is_deleted = 0', [cats[0].category_id]);

        if (!photos.length) return res.status(404).send('No photos in this category');

        const archive = archiver('zip', { zlib: { level: 9 } });
        res.attachment(`${req.params.categoryName}.zip`);
        archive.pipe(res);

        for (const photo of photos) {
            await new Promise((resolve) => {
                https.get(photo.file_path, (response) => {
                    if (response.statusCode === 200) {
                        archive.append(response, { name: photo.file_name });
                    }
                    response.on('end', resolve);
                    response.on('error', resolve);
                }).on('error', resolve);
            });
        }
        archive.finalize();
    } catch (e) {
        console.error('Zip Error:', e);
        if (!res.headersSent) res.status(500).send('Error creating zip');
    }
});

// ==========================================
// 🔥 ระบบทำความสะอาด Logs อัตโนมัติ (Log Retention)
// ==========================================
async function cleanOldLogs() {
    try {
        const DAYS_TO_KEEP = 90; 
        
        const [result] = await pool.query(
            'DELETE FROM Logs WHERE created_at < NOW() - INTERVAL ? DAY', 
            [DAYS_TO_KEEP]
        );
        
        if (result.affectedRows > 0) {
            console.log(`🧹 Auto-Clean: ลบ Logs เก่าเกิน ${DAYS_TO_KEEP} วัน จำนวน ${result.affectedRows} รายการ`);
        }
    } catch (err) {
        console.error('❌ Auto-Clean Logs Error:', err.message);
    }
}

cleanOldLogs();
setInterval(cleanOldLogs, 24 * 60 * 60 * 1000);

// 404 & Error Handler
app.use((req, res) => { res.status(404).json({ message: 'Route not found' }); });
app.use((err, req, res, next) => { console.error('Server error:', err); res.status(500).json({ error: 'Internal server error' }); });

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));