// UPDATE YOUR server.js WITH THIS BETTER CORS CONFIGURATION
// Replace the existing CORS setup at the very top

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Create Express app
const app = express();

// ============================================
// BETTER CORS CONFIGURATION
// ============================================
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:5173',
      'http://localhost:8080',
      'http://localhost:8000',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:8080',
      'http://127.0.0.1:8000'
    ];
    
    // Allow requests with no origin (mobile apps, curl requests, etc.)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(null, true); // Allow anyway for testing
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Add headers middleware for extra safety
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

// Secret key for JWT
const JWT_SECRET = 'your_secret_key_change_this_in_production';

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'aashu',
  database: 'hospital_db'
});

// Connect to database
db.connect((err) => {
  if (err) {
    console.log('❌ Database connection failed:', err.message);
  } else {
    console.log('✅ Connected to MySQL Database!');
  }
});

// Convert callback-based queries to promises
const query = (sql, params) => {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, results) => {
      if (err) reject(err);
      else resolve(results);
    });
  });
};

// ============================================
// TEST ROUTE
// ============================================
app.get('/api/test', (req, res) => {
  res.json({ 
    message: '🎉 Congratulations! Your backend is working!',
    timestamp: new Date(),
    cors: 'enabled',
    apiUrl: 'http://localhost:5000'
  });
});

// ... rest of your routes follow ...

// ============================================
// AUTHENTICATION ROUTES
// ============================================

// PUBLIC REGISTRATION - PATIENTS ONLY
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, phone, password, role } = req.body;

    // SECURITY: Only patients can self-register
    if (role !== 'patient') {
      return res.status(403).json({ 
        success: false, 
        message: 'Unauthorized. Only patients can self-register.' 
      });
    }

    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please fill all required fields' 
      });
    }

    const existingUser = await query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email already registered' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await query(
      'INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, phone, hashedPassword, 'patient']
    );

    const userId = result.insertId;
    await query('INSERT INTO patients (user_id) VALUES (?)', [userId]);

    res.json({ 
      success: true, 
      message: 'Registration successful! Please login.',
      userId: userId
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during registration' 
    });
  }
});

// LOGIN - ALL ROLES
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please provide email and password' 
      });
    }

    const users = await query('SELECT * FROM users WHERE email = ?', [email]);
    
    if (users.length === 0) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }

    const user = users[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }

    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ 
      success: true, 
      message: 'Login successful!',
      token: token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during login' 
    });
  }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  
  if (!token) {
    return res.status(403).json({ 
      success: false, 
      message: 'No token provided' 
    });
  }

  const actualToken = token.startsWith('Bearer ') ? token.slice(7) : token;

  jwt.verify(actualToken, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid or expired token' 
      });
    }
    req.user = decoded;
    next();
  });
};

// Middleware to check if user is Admin
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      success: false, 
      message: 'Access denied. Admin only.' 
    });
  }
  next();
};

app.get('/api/dashboard', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const role = req.user.role;

    const users = await query('SELECT id, name, email, role FROM users WHERE id = ?', [userId]);
    const user = users[0];

    res.json({
      success: true,
      message: `Welcome to ${role} dashboard!`,
      user: user
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// ============================================
// ADMIN ROUTES
// ============================================

// Add Doctor (Admin only)
app.post('/api/admin/add-doctor', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, email, phone, specialization, qualification, experience_years, consultation_fee } = req.body;

    if (!name || !email || !specialization) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please fill all required fields' 
      });
    }

    const existingUser = await query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email already exists' 
      });
    }

    const tempPassword = 'Doctor@' + Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    const result = await query(
      'INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, phone, hashedPassword, 'doctor']
    );

    const userId = result.insertId;

    await query(
      'INSERT INTO doctors (user_id, specialization, qualification, experience_years, consultation_fee) VALUES (?, ?, ?, ?, ?)',
      [userId, specialization, qualification, experience_years, consultation_fee]
    );

    res.json({ 
      success: true, 
      message: 'Doctor added successfully!',
      tempPassword: tempPassword,
      doctorId: userId
    });

  } catch (error) {
    console.error('Add doctor error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// Get all appointments (Admin only)
app.get('/api/admin/appointments', verifyToken, isAdmin, async (req, res) => {
  try {
    const appointments = await query(`
      SELECT 
        a.id,
        a.appointment_date,
        a.appointment_time,
        a.status,
        a.consultation_fee,
        a.payment_status,
        patient_user.name as patient_name,
        patient_user.phone as patient_phone,
        doctor_user.name as doctor_name,
        d.specialization
      FROM appointments a
      JOIN patients p ON a.patient_id = p.id
      JOIN users patient_user ON p.user_id = patient_user.id
      JOIN doctors d ON a.doctor_id = d.id
      JOIN users doctor_user ON d.user_id = doctor_user.id
      ORDER BY a.appointment_date DESC, a.appointment_time DESC
    `);

    res.json({
      success: true,
      appointments: appointments
    });

  } catch (error) {
    console.error('Get all appointments error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching appointments' 
    });
  }
});

// ============================================
// DOCTOR ROUTES
// ============================================

app.get('/api/doctors', async (req, res) => {
  try {
    const doctors = await query(`
      SELECT 
        d.id,
        u.name,
        d.specialization,
        d.qualification,
        d.experience_years,
        d.consultation_fee,
        d.available_days,
        d.start_time,
        d.end_time
      FROM doctors d
      JOIN users u ON d.user_id = u.id
      WHERE u.role = 'doctor'
    `);

    res.json({
      success: true,
      doctors: doctors
    });

  } catch (error) {
    console.error('Get doctors error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching doctors' 
    });
  }
});

app.get('/api/doctors/:id', async (req, res) => {
  try {
    const doctorId = req.params.id;

    const doctors = await query(`
      SELECT 
        d.id,
        u.name,
        u.email,
        u.phone,
        d.specialization,
        d.qualification,
        d.experience_years,
        d.consultation_fee,
        d.available_days,
        d.start_time,
        d.end_time,
        d.slot_duration
      FROM doctors d
      JOIN users u ON d.user_id = u.id
      WHERE d.id = ?
    `, [doctorId]);

    if (doctors.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Doctor not found' 
      });
    }

    res.json({
      success: true,
      doctor: doctors[0]
    });

  } catch (error) {
    console.error('Get doctor error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching doctor details' 
    });
  }
});

// Get doctor's appointments
app.get('/api/doctor/appointments', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    if (req.user.role !== 'doctor') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only doctors can view their appointments' 
      });
    }

    const doctors = await query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
    
    if (doctors.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Doctor profile not found' 
      });
    }

    const doctorId = doctors[0].id;

    const appointments = await query(`
      SELECT 
        a.id,
        a.appointment_date,
        a.appointment_time,
        a.status,
        a.consultation_fee,
        a.payment_status,
        u.name as patient_name,
        u.phone as patient_phone,
        u.email as patient_email
      FROM appointments a
      JOIN patients p ON a.patient_id = p.id
      JOIN users u ON p.user_id = u.id
      WHERE a.doctor_id = ?
      ORDER BY a.appointment_date DESC, a.appointment_time DESC
    `, [doctorId]);

    res.json({
      success: true,
      appointments: appointments
    });

  } catch (error) {
    console.error('Get doctor appointments error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching appointments' 
    });
  }
});
// ============================================
// DOCTOR AVAILABILITY ROUTES
// ============================================

// Get doctor's availability
app.get('/api/doctor/availability', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    if (req.user.role !== 'doctor') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only doctors can view availability' 
      });
    }

    const doctors = await query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
    
    if (doctors.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Doctor profile not found' 
      });
    }

    const doctorId = doctors[0].id;

    const availability = await query(
      `SELECT available_days, start_time, end_time, slot_duration 
       FROM doctors WHERE id = ?`,
      [doctorId]
    );

    res.json({
      success: true,
      availability: availability[0] || {
        available_days: '[]',
        start_time: '09:00:00',
        end_time: '17:00:00',
        slot_duration: 30
      }
    });

  } catch (error) {
    console.error('Get availability error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching availability' 
    });
  }
});

// Set doctor's availability
app.post('/api/doctor/availability', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { available_days, start_time, end_time, slot_duration } = req.body;

    if (req.user.role !== 'doctor') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only doctors can set availability' 
      });
    }

    if (!available_days || !start_time || !end_time || !slot_duration) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please fill all required fields' 
      });
    }

    const doctors = await query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
    
    if (doctors.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Doctor profile not found' 
      });
    }

    const doctorId = doctors[0].id;

    await query(
      `UPDATE doctors 
       SET available_days = ?, start_time = ?, end_time = ?, slot_duration = ?
       WHERE id = ?`,
      [JSON.stringify(available_days), start_time, end_time, slot_duration, doctorId]
    );

    res.json({
      success: true,
      message: 'Availability updated successfully!'
    });

  } catch (error) {
    console.error('Set availability error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error updating availability' 
    });
  }
});


// =============================================================
// UPDATED APPOINTMENT BOOKING ROUTES — FIXED SLOT STATUS API
// =============================================================


app.get('/api/doctor/:doctorId/available-slots/:date', async (req, res) => {
  try {
    const { doctorId, date } = req.params;

    const doctors = await query(
      `SELECT available_days, start_time, end_time, slot_duration 
       FROM doctors WHERE id = ?`,
      [doctorId]
    );

    if (doctors.length === 0) {
      return res.status(404).json({ success: false, message: 'Doctor not found' });
    }

    const doctor = doctors[0];
    const availableDays = JSON.parse(doctor.available_days || '[]');

    const dateObj = new Date(date);
    const dayName = dateObj.toLocaleDateString('en-US', { weekday: 'long' });

    if (!availableDays.includes(dayName)) {
      return res.json({ success: true, slots: [], dayName });
    }

    // Get booked & locked slots
    const busySlots = await query(
      `SELECT slot_time, is_booked, locked_until 
       FROM doctor_slots
       WHERE doctor_id = ? AND slot_date = ?
       AND (is_booked = TRUE OR (locked_until IS NOT NULL AND locked_until > NOW()))`,
      [doctorId, date]
    );

    const busyMap = {};
    busySlots.forEach(s => {
      busyMap[s.slot_time] = {
        booked: s.is_booked,
        locked: !s.is_booked
      };
    });

    // Generate ALL slots
    const slots = [];
    let [h, m] = doctor.start_time.split(':').map(Number);
    const [endH, endM] = doctor.end_time.split(':').map(Number);
    const duration = doctor.slot_duration;

    while (h < endH || (h === endH && m < endM)) {
      const timeStr = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:00`;

      if (busyMap[timeStr]) {
        slots.push({
          time: timeStr,
          available: false,
          booked: busyMap[timeStr].booked,
          locked: busyMap[timeStr].locked
        });
      } else {
        slots.push({
          time: timeStr,
          available: true
        });
      }

      m += duration;
      if (m >= 60) {
        h += Math.floor(m / 60);
        m %= 60;
      }
    }

    res.json({
      success: true,
      dayName,
      slots
    });

  } catch (error) {
    console.error('Slot API Error:', error);
    res.status(500).json({ success: false, message: 'Slot fetch failed' });
  }
});


// Lock a slot (UPDATED - more robust)
app.post('/api/slots/lock', verifyToken, async (req, res) => {
  try {
    const { doctorId, date, time } = req.body;
    const userId = req.user.userId;

    if (!doctorId || !date || !time) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing required fields' 
      });
    }

    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    
    if (patients.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Only patients can book appointments' 
      });
    }

    const patientId = patients[0].id;

    // Check if slot is already booked or locked
    const existingSlots = await query(
      `SELECT * FROM doctor_slots 
       WHERE doctor_id = ? AND slot_date = ? AND slot_time = ?
       AND (is_booked = TRUE OR (locked_until IS NOT NULL AND locked_until > NOW()))`,
      [doctorId, date, time]
    );

    if (existingSlots.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Slot is no longer available' 
      });
    }

    // ⏱️ CHANGED: Lock the slot for 90 SECONDS (previously was 5 minutes)
    const lockUntil = new Date(Date.now() + 90 * 1000); // 90 seconds = 90 * 1000 milliseconds

    await query(
      `INSERT INTO doctor_slots (doctor_id, slot_date, slot_time, locked_until, patient_id, is_booked)
       VALUES (?, ?, ?, ?, ?, FALSE)
       ON DUPLICATE KEY UPDATE locked_until = ?, patient_id = ?`,
      [doctorId, date, time, lockUntil, patientId, lockUntil, patientId]
    );

    res.json({
      success: true,
      message: 'Slot locked for 90 seconds', // ⏱️ CHANGED: Updated message
      lockedUntil: lockUntil,
      lockDurationSeconds: 90 // ⏱️ CHANGED: from 300 to 90
    });

  } catch (error) {
    console.error('Lock slot error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error locking slot' 
    });
  }
});

// Confirm appointment after payment (UPDATED)
app.post('/api/appointments/confirm', verifyToken, async (req, res) => {
  try {
    const { doctorId, date, time, paymentId } = req.body;
    const userId = req.user.userId;

    if (!doctorId || !date || !time || !paymentId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing required fields' 
      });
    }

    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    
    if (patients.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Patient profile not found' 
      });
    }

    const patientId = patients[0].id;

    // Get consultation fee
    const doctors = await query('SELECT consultation_fee FROM doctors WHERE id = ?', [doctorId]);
    
    if (doctors.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Doctor not found' 
      });
    }

    const consultationFee = doctors[0].consultation_fee;

    // Check if slot is still locked/available
    const lockedSlot = await query(
      `SELECT * FROM doctor_slots 
       WHERE doctor_id = ? AND slot_date = ? AND slot_time = ? AND patient_id = ?
       AND (locked_until IS NOT NULL AND locked_until > NOW())`,
      [doctorId, date, time, patientId]
    );

    if (lockedSlot.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Slot expired or unavailable' 
      });
    }

    // Update slot to booked
    await query(
      `UPDATE doctor_slots 
       SET is_booked = TRUE, locked_until = NULL 
       WHERE doctor_id = ? AND slot_date = ? AND slot_time = ? AND patient_id = ?`,
      [doctorId, date, time, patientId]
    );

    // Create appointment
    const result = await query(
      `INSERT INTO appointments 
       (patient_id, doctor_id, appointment_date, appointment_time, status, consultation_fee, payment_status, payment_id)
       VALUES (?, ?, ?, ?, 'confirmed', ?, 'paid', ?)`,
      [patientId, doctorId, date, time, consultationFee, paymentId]
    );

    res.json({
      success: true,
      message: 'Appointment confirmed successfully!',
      appointmentId: result.insertId,
      status: 'confirmed'
    });

  } catch (error) {
    console.error('Confirm appointment error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error confirming appointment' 
    });
  }
});

// Auto-unlock expired slots (Run periodically - optional background job)
app.post('/api/admin/cleanup-expired-slots', verifyToken, isAdmin, async (req, res) => {
  try {
    const result = await query(
      `UPDATE doctor_slots 
       SET locked_until = NULL, patient_id = NULL 
       WHERE locked_until IS NOT NULL AND locked_until < NOW() AND is_booked = FALSE`
    );

    res.json({
      success: true,
      message: 'Expired slots cleaned up',
      affectedRows: result.affectedRows
    });

  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error cleaning up slots' 
    });
  }
});
// ============================================
// PATIENT APPOINTMENT ROUTES
// ============================================

// GET patient's appointments
app.get('/api/appointments/my', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Check if user is a patient
    if (req.user.role !== 'patient') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only patients can view their appointments' 
      });
    }

    // Get patient ID from user
    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    
    if (patients.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Patient profile not found' 
      });
    }

    const patientId = patients[0].id;

    // Get all appointments for this patient
    const appointments = await query(`
      SELECT 
        a.id,
        a.appointment_date,
        a.appointment_time,
        a.status,
        a.consultation_fee,
        a.payment_status,
        u.name as doctor_name,
        d.specialization
      FROM appointments a
      JOIN doctors d ON a.doctor_id = d.id
      JOIN users u ON d.user_id = u.id
      WHERE a.patient_id = ?
      ORDER BY a.appointment_date DESC, a.appointment_time DESC
    `, [patientId]);

    res.json({
      success: true,
      appointments: appointments
    });

  } catch (error) {
    console.error('Get appointments error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching appointments' 
    });
  }
});

// CANCEL appointment
app.post('/api/appointments/:id/cancel', verifyToken, async (req, res) => {
  try {
    const appointmentId = req.params.id;
    const userId = req.user.userId;
    const { reason } = req.body;

    // Get patient ID
    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    
    if (patients.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Patient profile not found' 
      });
    }

    const patientId = patients[0].id;

    // Get appointment details
    const appointments = await query(
      'SELECT * FROM appointments WHERE id = ? AND patient_id = ?',
      [appointmentId, patientId]
    );

    if (appointments.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Appointment not found' 
      });
    }

    const appointment = appointments[0];

    // Update appointment status to cancelled
    await query(
      `UPDATE appointments 
       SET status = 'cancelled', cancelled_by = 'patient', cancellation_reason = ?, refund_status = 'completed'
       WHERE id = ?`,
      [reason || 'Cancelled by patient', appointmentId]
    );

    // Delete from doctor_slots
    await query(
      `DELETE FROM doctor_slots 
       WHERE doctor_id = ? AND slot_date = ? AND slot_time = ?`,
      [appointment.doctor_id, appointment.appointment_date, appointment.appointment_time]
    );

    res.json({
      success: true,
      message: 'Appointment cancelled. Refund will be processed.'
    });

  } catch (error) {
    console.error('Cancel appointment error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error cancelling appointment' 
    });
  }
});

// GET patient's medical history (past appointments with prescriptions)
app.get('/api/prescriptions/my', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    if (req.user.role !== 'patient') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only patients can view medical history' 
      });
    }

    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    
    if (patients.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Patient profile not found' 
      });
    }

    const patientId = patients[0].id;

    // Get prescriptions with appointment details
    const prescriptions = await query(`
      SELECT 
        p.id,
        p.medicines,
        p.dosage,
        p.duration,
        p.remarks,
        p.problem_description,
        p.diagnosis,
        p.advice,
        p.created_at,
        a.appointment_date,
        a.appointment_time,
        u.name as doctor_name,
        d.specialization
      FROM prescriptions p
      JOIN appointments a ON p.appointment_id = a.id
      JOIN doctors d ON a.doctor_id = d.id
      JOIN users u ON d.user_id = u.id
      WHERE p.patient_id = ?
      ORDER BY p.created_at DESC
    `, [patientId]);

    res.json({
      success: true,
      prescriptions: prescriptions
    });

  } catch (error) {
    console.error('Get prescriptions error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching medical history' 
    });
  }
});

// ============================================
// PATIENT PROFILE ROUTES
// ============================================

// GET patient profile
app.get('/api/patient/profile', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    if (req.user.role !== 'patient') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only patients can access their profile' 
      });
    }

    console.log('📡 Fetching profile for userId:', userId);

    // Get patient data - handle missing columns gracefully
    const patients = await query(`
      SELECT 
        p.id,
        p.user_id,
        COALESCE(p.patient_id, CONCAT('P', p.id)) as patient_id,
        COALESCE(p.full_name, '') as full_name,
        COALESCE(p.mobile, '') as mobile,
        COALESCE(p.alternate_mobile, '') as alternate_mobile,
        COALESCE(p.address, '') as address,
        COALESCE(p.dob, '') as dob,
        COALESCE(p.age, 0) as age,
        COALESCE(p.gender, '') as gender,
        COALESCE(p.blood_group, '') as blood_group,
        COALESCE(p.marital_status, '') as marital_status,
        COALESCE(p.occupation, '') as occupation,
        COALESCE(p.height, 0) as height,
        COALESCE(p.weight, 0) as weight,
        COALESCE(p.allergies, '') as allergies,
        COALESCE(p.existing_diseases, '') as existing_diseases,
        COALESCE(p.emergency_contact_name, '') as emergency_contact_name,
        COALESCE(p.emergency_contact_number, '') as emergency_contact_number,
        COALESCE(p.relationship, '') as relationship,
        NOW() as created_at,
        u.email,
        u.name
      FROM patients p
      JOIN users u ON p.user_id = u.id
      WHERE p.user_id = ?
    `, [userId]);

    console.log('✅ Patients found:', patients.length);

    if (patients.length === 0) {
      console.log('❌ No patient profile found for userId:', userId);
      return res.status(404).json({ 
        success: false, 
        message: 'Patient profile not found' 
      });
    }

    const patient = patients[0];
    console.log('✅ Patient data retrieved:', patient.patient_id);

    res.json({
      success: true,
      patient: patient
    });

  } catch (error) {
    console.error('❌ Get patient profile error:', error.message);
    console.error('Stack:', error.stack);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching profile: ' + error.message
    });
  }
});

// UPDATE patient profile
app.put('/api/patient/profile', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const {
      full_name,
      email,
      mobile,
      alternate_mobile,
      address,
      dob,
      gender,
      blood_group,
      marital_status,
      occupation,
      height,
      weight,
      allergies,
      existing_diseases,
      emergency_contact_name,
      emergency_contact_number,
      relationship
    } = req.body;

    console.log('📝 Updating profile for userId:', userId);

    if (req.user.role !== 'patient') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only patients can update their profile' 
      });
    }

    // Validate required fields
    if (!full_name || !email || !mobile || !address || !dob) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please fill all required fields: name, email, mobile, address, DOB' 
      });
    }

    // Get patient ID
    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    
    if (patients.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Patient profile not found' 
      });
    }

    const patientId = patients[0].id;

    // Calculate age from DOB
    const dobDate = new Date(dob);
    const today = new Date();
    let age = today.getFullYear() - dobDate.getFullYear();
    const monthDiff = today.getMonth() - dobDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < dobDate.getDate())) {
      age--;
    }

    console.log('✅ Calculated age:', age);

    // Update patients table
    const updateResult = await query(`
      UPDATE patients SET
        full_name = ?,
        mobile = ?,
        alternate_mobile = ?,
        address = ?,
        dob = ?,
        age = ?,
        gender = ?,
        blood_group = ?,
        marital_status = ?,
        occupation = ?,
        height = ?,
        weight = ?,
        allergies = ?,
        existing_diseases = ?,
        emergency_contact_name = ?,
        emergency_contact_number = ?,
        relationship = ?
      WHERE id = ?
    `, [
      full_name,
      mobile,
      alternate_mobile,
      address,
      dob,
      age,
      gender,
      blood_group,
      marital_status,
      occupation,
      height,
      weight,
      allergies,
      existing_diseases,
      emergency_contact_name,
      emergency_contact_number,
      relationship,
      patientId
    ]);

    console.log('✅ Updated rows:', updateResult.affectedRows);

    // Update email in users table if changed
    await query('UPDATE users SET email = ? WHERE id = ?', [email, userId]);

    console.log('✅ Email updated in users table');

    res.json({
      success: true,
      message: '✅ Profile updated successfully!'
    });

  } catch (error) {
    console.error('❌ Update patient profile error:', error.message);
    console.error('Stack:', error.stack);
    res.status(500).json({ 
      success: false, 
      message: 'Error updating profile: ' + error.message
    });
  }
});

// ============================================
// PRESCRIPTION ROUTES
// ============================================

app.get('/api/prescriptions/my', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    
    if (patients.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Only patients can view medical history' 
      });
    }

    const patientId = patients[0].id;

    const prescriptions = await query(`
      SELECT 
        p.id,
        p.medicines,
        p.dosage,
        p.duration,
        p.remarks,
        p.problem_description,
        p.diagnosis,
        p.advice,
        p.created_at,
        a.appointment_date,
        a.appointment_time,
        u.name as doctor_name,
        d.specialization
      FROM prescriptions p
      JOIN appointments a ON p.appointment_id = a.id
      JOIN doctors d ON a.doctor_id = d.id
      JOIN users u ON d.user_id = u.id
      WHERE p.patient_id = ?
      ORDER BY p.created_at DESC
    `, [patientId]);

    res.json({
      success: true,
      prescriptions: prescriptions
    });

  } catch (error) {
    console.error('Get prescriptions error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching medical history' 
    });
  }
});

app.post('/api/prescriptions/create', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { 
      appointmentId, 
      medicines, 
      dosage, 
      duration, 
      remarks, 
      problemDescription, 
      diagnosis, 
      advice 
    } = req.body;

    if (req.user.role !== 'doctor') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only doctors can create prescriptions' 
      });
    }

    const doctors = await query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
    const doctorId = doctors[0].id;

    const appointments = await query(
      'SELECT patient_id, doctor_id FROM appointments WHERE id = ?',
      [appointmentId]
    );

    if (appointments.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Appointment not found' 
      });
    }

    const appointment = appointments[0];

    if (appointment.doctor_id !== doctorId) {
      return res.status(403).json({ 
        success: false, 
        message: 'You can only create prescriptions for your own patients' 
      });
    }

    const existing = await query(
      'SELECT id FROM prescriptions WHERE appointment_id = ?',
      [appointmentId]
    );

    if (existing.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Prescription already exists for this appointment' 
      });
    }

    const result = await query(
      `INSERT INTO prescriptions 
       (appointment_id, patient_id, doctor_id, medicines, dosage, duration, remarks, problem_description, diagnosis, advice)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [appointmentId, appointment.patient_id, doctorId, medicines, dosage, duration, remarks, problemDescription, diagnosis, advice]
    );

    await query(
      'UPDATE appointments SET status = "completed" WHERE id = ?',
      [appointmentId]
    );

    res.json({
      success: true,
      message: 'Prescription created successfully',
      prescriptionId: result.insertId
    });

  } catch (error) {
    console.error('Create prescription error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error creating prescription' 
    });
  }
});

// Start server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  console.log(`📡 Test your API at: http://localhost:${PORT}/api/test`);
  console.log(`🔐 Secure authentication system active!`);
  console.log(`📅 Appointment booking system ready!`);
  console.log(`⚠️  SECURITY: Only patients can self-register!`);
});