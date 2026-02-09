// create_admin.js (ฉบับแก้ Foreign Key Constraint)
require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 4000,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME || 'army_photo_gallery',
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
});

(async () => {
    try {
        const password = '1234'; // รหัสผ่านที่จะใช้
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 1. เช็คก่อนว่ามี user ชื่อ admin หรือยัง?
        const [users] = await pool.query('SELECT * FROM Users WHERE username = ?', ['admin']);

        if (users.length > 0) {
            // 2A. ถ้ามีแล้ว -> แค่อัปเดตรหัสผ่าน (ไม่ลบ user ทิ้ง รูปเลยไม่หาย)
            await pool.query('UPDATE Users SET password = ?, role = ? WHERE username = ?', 
                [hashedPassword, 'admin', 'admin']);
            console.log('✅ พบ Admin เดิม: ทำการรีเซ็ตรหัสผ่านเป็น "1234" เรียบร้อย!');
        } else {
            // 2B. ถ้ายังไม่มี -> สร้างใหม่
            await pool.query('INSERT INTO Users (username, password, role) VALUES (?, ?, ?)', 
                ['admin', hashedPassword, 'admin']);
            console.log('✅ สร้าง User: "admin" / Pass: "1234" ใหม่สำเร็จ!');
        }

    } catch (err) {
        console.error('❌ เกิดข้อผิดพลาด:', err.message);
    } finally {
        process.exit();
    }
})();