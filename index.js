import express from 'express'
import mongoose from 'mongoose'
import cors from 'cors'
import dotenv from 'dotenv'
import multer from 'multer'
import path from 'path'
import fs from 'fs'
import bcrypt from 'bcryptjs'
import helmet from 'helmet'
import session from 'express-session'
import cookieParser from 'cookie-parser'
import rateLimit from 'express-rate-limit'
import jwt from 'jsonwebtoken'
import MentorApplication from './models/MentorApplication.js'
import isAdmin from './middleware/isAdmin.js'

// Load environment variables
dotenv.config()

// Initialize Express app
const app = express()

// Security middleware
app.use(helmet())
app.use(express.json())
app.use(cookieParser())
// CORS for frontend dev server (send cookies)
app.use(
  cors({
    origin: ['http://localhost:5173'],
    credentials: true
  })
)

// Session configuration
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_insecure_secret_change_me'
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false, 
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 8 // 8 hours
    }
  })
)

// Static files
app.use('/uploads', express.static(path.resolve('uploads')))

// Database connection
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/Clarity_Call'

mongoose.set('strictQuery', true)
mongoose
  .connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err)
    process.exit(1)
  })

// User Schema
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true, lowercase: true, unique: true },
  password: { type: String, required: true },
  profileImage: { type: String, default: '' },
  bio: { type: String, default: '' },
  title: { type: String, default: '' },
  expertise: { type: [String], default: [] },
  isBlocked: { type: Boolean, default: false },
  lastActiveAt: { type: Date },
  role: { type: String, enum: ['user', 'mentor', 'admin'], default: 'user' }
}, { timestamps: true })

const User = mongoose.model('User', userSchema)

// Auth middleware
const requireAuth = (req, res, next) => {
  if (req.session?.user) return next()
  return res.status(401).json({ message: 'Unauthorized' })
}

const requireAdmin = (req, res, next) => {
  if (req.session?.user?.role === 'admin') return next()
  return res.status(403).json({ message: 'Forbidden' })
}

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
})

// Routes
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { firstName, lastName, email, password, bio, title, expertise } = req.body
    
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' })
    }

    const existing = await User.findOne({ email })
    if (existing) {
      return res.status(409).json({ message: 'Email already registered' })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const user = await User.create({
      firstName,
      lastName, 
      email,
      password: hashedPassword,
      bio,
      title,
      expertise
    })

    return res.status(201).json(user)
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// File upload configuration
const uploadsDir = path.resolve('uploads')
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true })
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname)
    const base = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9-_]/g, '')
    cb(null, `${base}-${Date.now()}${ext}`)
  }
})

const upload = multer({ storage })

// API Routes
app.post('/api/users/:id/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const { id } = req.params
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' })
    }

    const relativePath = `/uploads/${req.file.filename}`
    const user = await User.findByIdAndUpdate(
      id,
      { profileImage: relativePath },
      { new: true }
    )

    if (!user) {
      return res.status(404).json({ message: 'User not found' })
    }

    return res.status(200).json({
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      profileImage: user.profileImage
    })
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Login route
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' })
    }

    const user = await User.findOne({ email })
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    // Set session
    req.session.user = {
      id: user._id,
      email: user.email,
      role: user.role
    }

    return res.status(200).json({
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role
    })

  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Profile update
app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    const { id, firstName, lastName, title, bio, expertise } = req.body

    const user = await User.findById(id)
    if (!user) {
      return res.status(404).json({ message: 'User not found' })
    }

    user.firstName = firstName
    user.lastName = lastName
    user.title = title
    user.bio = bio
    user.expertise = expertise

    await user.save()
    
    return res.status(200).json(user)
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Admin - Get all mentor applications
app.get('/admin/mentor-applications', requireAuth, isAdmin, async (req, res) => {
  try {
    const applications = await MentorApplication.find({}).populate('userId', 'firstName lastName email');
    res.status(200).json(applications);
  } catch (error) {
    console.error('Error fetching mentor applications:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin - Update mentor application status
app.put('/admin/mentor-applications/:id/status', requireAuth, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!['approved', 'rejected', 'pending'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const application = await MentorApplication.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );

    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }

    // If approved, update user role to mentor
    if (status === 'approved') {
      await User.findByIdAndUpdate(application.userId, { role: 'mentor' });
    }

    res.status(200).json(application);
  } catch (error) {
    console.error('Error updating mentor application status:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Mentor - Create or update an application
app.post('/api/mentor-applications', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { name, phoneNumber, bio, domain, linkedin, portfolio } = req.body;

    const update = { name, phoneNumber, bio, domain, linkedin, portfolio };

    const application = await MentorApplication.findOneAndUpdate(
      { userId },
      { $set: update, $setOnInsert: { userId } },
      { upsert: true, new: true }
    );

    return res.status(200).json(application);
  } catch (error) {
    console.error('Error creating mentor application:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Start server
const PORT = process.env.PORT || 5001
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
