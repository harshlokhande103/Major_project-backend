import express from 'express'
import mongoose from 'mongoose'
import cors from 'cors'
import dotenv from 'dotenv'
import multer from 'multer'
import { v2 as cloudinary } from 'cloudinary'
import bcrypt from 'bcryptjs'
import helmet from 'helmet'
import session from 'express-session'
import MongoStore from 'connect-mongo'
import cookieParser from 'cookie-parser'
import rateLimit from 'express-rate-limit'
import MentorApplication from './models/MentorApplication.js'
import Notification from './models/Notification.js'
import Slot from './models/Slot.js'
import Booking from './models/Booking.js'
import pagesRouter from './routes/pages.js'
import chatRouter from './routes/chat.js'
import mentorRouter from './routes/mentor.js'

// Load environment variables
dotenv.config()

const app = express()

// Security middleware
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' }
  })
)

// Replace simple express.json() with a version that captures the raw body for debugging
app.use(express.json({
  limit: '1mb',
  verify: (req, res, buf) => {
    try {
      req.rawBody = buf.toString('utf8');
    } catch (e) {
      req.rawBody = '';
    }
  }
}))

// Also accept urlencoded bodies and capture raw body (useful if client mis-sets Content-Type)
app.use(express.urlencoded({
  extended: true,
  limit: '1mb',
  verify: (req, res, buf) => {
    try {
      req.rawBody = buf.toString('utf8');
    } catch (e) {
      req.rawBody = '';
    }
  }
}))

app.use(cookieParser())

// Improved JSON parse error handler that logs a truncated raw body and gives a clearer hint
app.use((err, req, res, next) => {
  if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError)) {
    const raw = String(req.rawBody || '').slice(0, 200) // truncate for logs
    console.warn('Malformed JSON body:', err.message)
    if (raw) console.warn('Raw request start:', raw.replace(/\r?\n/g, '\\n'))
    return res.status(400).json({
      ok: false,
      message: 'Malformed JSON in request body. Ensure Content-Type: application/json and valid JSON payload.',
      hint: 'If using Postman: Body → raw → JSON (application/json). Remove any stray characters or trailing commas.'
    })
  }
  return next(err)
})

// Trust proxy for secure cookies behind proxies
app.set('trust proxy', 1)

const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'https://major-project-frontend-five.vercel.app'
  ],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  optionsSuccessStatus: 204
}
app.use(cors(corsOptions))
app.options('*', cors(corsOptions))

// Session configuration
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_insecure_secret_change_me'
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.error('SESSION_SECRET must be set in production')
}
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/Clarity_Call',
      collectionName: 'sessions',
      stringify: false,
      ttl: 60 * 60 * 8
    }),
    cookie: {
      httpOnly: true,
      secure: !!process.env.VERCEL || process.env.NODE_ENV === 'production',
      sameSite: (!!process.env.VERCEL || process.env.NODE_ENV === 'production') ? 'none' : 'lax',
      maxAge: 1000 * 60 * 60 * 8
    }
  })
)

let mongoConnected = false
app.get('/api/health', (req, res) => {
  res.status(200).json({ ok: true, mongoConnected })
})

const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/Clarity_Call'
if (process.env.NODE_ENV === 'production' && !process.env.MONGODB_URI) {
  console.error('MONGODB_URI must be set in production')
}

mongoose.set('strictQuery', true)
mongoose
  .connect(mongoUri)
  .then(() => {
    console.log('MongoDB connected')
    mongoConnected = true
  })
  .catch(err => {
    console.error('MongoDB connection error:', err)
  })

// Register routers
app.use('/api/mentors', mentorRouter)
app.use('/api/pages', pagesRouter)
app.use('/pages', pagesRouter)
app.use('/api/chat', chatRouter)

// User model
const userSchema = new mongoose.Schema(
  {
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true, unique: true },
    password: { type: String, required: true },
    profileImage: { type: String, default: '' },
    profileImageData: { type: Buffer },
    profileImageContentType: { type: String, default: '' },
    bio: { type: String, default: '' },
    title: { type: String, default: '' },
    field: { type: String, default: '' },
    expertise: { type: [String], default: [] },
    isBlocked: { type: Boolean, default: false },
    lastActiveAt: { type: Date },
    role: { type: String, enum: ['user', 'mentor', 'admin'], default: 'user' }
  },
  { timestamps: true }
)
const User = mongoose.model('User', userSchema)

// Auth middleware (session preferred, falls back to Basic Auth or body creds)
const requireAuth = async (req, res, next) => {
  try {
    if (req.session?.user) return next()

    let email, password
    const authHeader = req.headers?.authorization || ''
    if (authHeader.startsWith('Basic ')) {
      const token = authHeader.slice(6)
      const decoded = Buffer.from(token, 'base64').toString('utf8')
      const sep = decoded.indexOf(':')
      if (sep !== -1) {
        email = decoded.slice(0, sep)
        password = decoded.slice(sep + 1)
      } else {
        email = decoded
      }
    }

    if ((!email || !password) && req.body && req.body.email && req.body.password) {
      email = req.body.email
      password = req.body.password
    }

    if (email && password) {
      const user = await User.findOne({ email })
      if (user && (await bcrypt.compare(String(password), user.password))) {
        req.session.user = { id: user._id, email: user.email, role: user.role }
        return next()
      }
    }
  } catch (err) {
    console.error('requireAuth fallback error:', err)
  }
  return res.status(401).json({ message: 'Unauthorized' })
}

// Admin middleware
const requireAdmin = async (req, res, next) => {
  try {
    if (req.session?.user && req.session.user.role === 'admin') return next()

    let email, password
    const authHeader = req.headers?.authorization || ''
    if (authHeader.startsWith('Basic ')) {
      const token = authHeader.slice(6)
      const decoded = Buffer.from(token, 'base64').toString('utf8')
      const sep = decoded.indexOf(':')
      if (sep !== -1) {
        email = decoded.slice(0, sep)
        password = decoded.slice(sep + 1)
      } else {
        email = decoded
      }
    }
    if ((!email || !password) && req.body && req.body.email && req.body.password) {
      email = req.body.email
      password = req.body.password
    }

    if (email && password) {
      const user = await User.findOne({ email })
      if (user && (await bcrypt.compare(String(password), user.password))) {
        if (String(user.role) === 'admin') {
          req.session.user = { id: user._id, email: user.email, role: user.role }
          return next()
        }
        return res.status(403).json({ message: 'Access denied. Admin privileges required.' })
      }
    }
  } catch (err) {
    console.error('requireAdmin fallback error:', err)
  }
  return res.status(403).json({ message: 'Access denied. Admin privileges required.' })
}

// Multer memory storage
const storage = multer.memoryStorage()
const upload = multer({ storage })

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
})

// Optional Cloudinary config
if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  })
}

// Register /api/register
app.post('/api/register', authLimiter, upload.single('profileImage'), async (req, res) => {
  try {
    let { firstName, lastName, name, email, password, bio, title, field, expertise } = req.body || {}

    if ((!firstName || !lastName) && name && typeof name === 'string') {
      const parts = name.trim().split(/\s+/)
      if (!firstName) firstName = parts.shift() || ''
      if (!lastName) lastName = parts.join(' ') || lastName || ''
    }

    firstName = firstName ? String(firstName).trim() : ''
    lastName = lastName ? String(lastName).trim() : ''
    email = email ? String(email).trim().toLowerCase() : ''
    password = password ? String(password) : ''

    const required = { firstName, lastName, email, password }
    const missing = Object.keys(required).filter(k => !required[k])
    if (missing.length > 0) {
      return res.status(400).json({ message: 'Missing required fields', missing })
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' })
    }

    const existing = await User.findOne({ email })
    if (existing) {
      return res.status(409).json({ message: 'Email already registered' })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    let expertiseArr = []
    if (Array.isArray(expertise)) expertiseArr = expertise
    else if (typeof expertise === 'string' && expertise.trim() !== '') expertiseArr = expertise.split(',').map(s => s.trim()).filter(Boolean)

    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      bio: bio || '',
      title: title || '',
      field: field || '',
      expertise: expertiseArr,
      profileImage: ''
    })

    if (req.file && req.file.buffer) {
      user.profileImageData = req.file.buffer
      user.profileImageContentType = req.file.mimetype || 'application/octet-stream'
      user.profileImage = `/api/users/${user._id}/avatar`
      await user.save()
    }

    const safe = {
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      profileImage: user.profileImage,
      bio: user.bio,
      title: user.title,
      field: user.field,
      expertise: user.expertise,
      role: user.role
    }

    return res.status(201).json(safe)
  } catch (err) {
    console.error('Register error:', err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Root
app.get('/', (req, res) => {
  res.send('Welcome to the Backend API!')
})

// Routes that depend on models / handlers

// Avatar upload
app.post('/api/users/:id/avatar', upload.single('avatar'), async (req, res) => {
  try {
    let { id } = req.params
    let targetUserId = id
    if (typeof id === 'string' && id.startsWith(':')) {
      if (req.session?.user?.id) targetUserId = String(req.session.user.id)
      else return res.status(400).json({ message: 'Invalid user id — replace ":id" with a real MongoDB ObjectId or authenticate.' })
    }

    if (!mongoose.Types.ObjectId.isValid(String(targetUserId))) return res.status(400).json({ message: 'Invalid user id' })

    const user = await User.findById(targetUserId)
    if (!user) return res.status(404).json({ message: 'User not found' })

    if (req.file && req.file.buffer) {
      user.profileImageData = req.file.buffer
      user.profileImageContentType = req.file.mimetype || 'application/octet-stream'
      user.profileImage = `/api/users/${user._id}/avatar`
      await user.save()
      return res.status(200).json({ id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName, profileImage: user.profileImage })
    }

    if (req.is('application/json') && (req.body?.base64 || req.body?.dataUrl || req.body?.file)) {
      let base64 = req.body.base64 || ''
      let contentType = req.body.contentType || 'application/octet-stream'
      if (!base64 && req.body.dataUrl) {
        const m = String(req.body.dataUrl).match(/^data:([^;]+);base64,(.*)$/)
        if (m) {
          contentType = m[1]
          base64 = m[2]
        }
      }
      if (!base64 && typeof req.body.file === 'string') base64 = req.body.file
      if (!base64) return res.status(400).json({ message: 'No file uploaded' })
      const buffer = Buffer.from(base64, 'base64')
      user.profileImageData = buffer
      user.profileImageContentType = contentType
      user.profileImage = `/api/users/${user._id}/avatar`
      await user.save()
      return res.status(200).json({ id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName, profileImage: user.profileImage })
    }

    return res.status(400).json({ message: 'No file uploaded. Use multipart/form-data (key "avatar") or JSON base64 payload.' })
  } catch (err) {
    console.error('Avatar upload error:', err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Serve avatar
app.get('/api/users/:id/avatar', async (req, res) => {
  try {
    const { id } = req.params
    const user = await User.findById(id).select('profileImageData profileImageContentType')
    if (!user || !user.profileImageData) return res.status(404).json({ message: 'Avatar not found' })
    res.setHeader('Content-Type', user.profileImageContentType || 'application/octet-stream')
    return res.status(200).send(user.profileImageData)
  } catch (err) {
    console.error('Avatar fetch error', err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Login
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required' })
    const user = await User.findOne({ email })
    if (!user) return res.status(401).json({ message: 'Invalid credentials' })
    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' })
    req.session.user = { id: user._id, email: user.email, role: user.role }
    return res.status(200).json({ id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName, profileImage: user.profileImage, bio: user.bio, title: user.title, field: user.field, expertise: user.expertise, role: user.role })
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Profile
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id
    const user = await User.findById(userId).select('-password')
    if (!user) return res.status(404).json({ message: 'User not found' })
    return res.status(200).json(user)
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Public users
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({}, 'firstName lastName email profileImage role field bio').lean()
    return res.status(200).json(Array.isArray(users) ? users : [])
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

app.get('/api/user/:id', async (req, res) => {
  try {
    let { id } = req.params
    if (typeof id === 'string' && id.startsWith(':')) return res.redirect(302, '/api/users')
    if (!mongoose.Types.ObjectId.isValid(String(id))) return res.status(400).json({ message: 'Invalid user id' })
    const user = await User.findById(id).select('-password').lean()
    if (!user) return res.status(404).json({ message: 'User not found' })
    return res.status(200).json(user)
  } catch (err) {
    console.error('GET /api/user/:id error', err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Profile update
app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    const sessionUserId = req.session?.user?.id
    const bodyId = req.body?.id
    const targetId = sessionUserId || bodyId
    if (!targetId) return res.status(401).json({ message: 'Unauthorized: no user id in session or request body' })
    if (!mongoose.Types.ObjectId.isValid(String(targetId))) return res.status(400).json({ message: 'Invalid user id' })
    const user = await User.findById(targetId)
    if (!user) return res.status(404).json({ message: 'User not found' })
    const { firstName, lastName, title, bio, expertise, field } = req.body || {}
    let didUpdate = false
    if (typeof firstName !== 'undefined') { user.firstName = firstName; didUpdate = true }
    if (typeof lastName !== 'undefined')  { user.lastName  = lastName;  didUpdate = true }
    if (typeof title !== 'undefined')     { user.title     = title;     didUpdate = true }
    if (typeof bio !== 'undefined')       { user.bio       = bio;       didUpdate = true }
    if (typeof field !== 'undefined')     { user.field     = field;     didUpdate = true }
    if (typeof expertise !== 'undefined') {
      if (Array.isArray(expertise)) user.expertise = expertise
      else if (typeof expertise === 'string') user.expertise = expertise.split(',').map(s => s.trim()).filter(Boolean)
      didUpdate = true
    }
    if (!didUpdate) return res.status(200).json(user)
    await user.save()
    return res.status(200).json(user)
  } catch (err) {
    console.error('Error updating profile:', err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Admin endpoints
const handleGetMentorApplications = async (req, res) => {
  try {
    const { status } = req.query
    let filter = {}
    if (status && ['pending', 'approved', 'rejected'].includes(status)) filter.status = status
    const applications = await MentorApplication.find(filter).populate('userId', 'firstName lastName email')
    res.status(200).json(applications)
  } catch (error) {
    console.error('Error fetching mentor applications:', error)
    res.status(500).json({ message: 'Server error' })
  }
}

app.get('/admin/mentor-applications', requireAuth, requireAdmin, handleGetMentorApplications)
app.get('/api/admin/mentor-applications', requireAuth, requireAdmin, handleGetMentorApplications)

const handleGetMentorApplicationCounts = async (req, res) => {
  try {
    const counts = await MentorApplication.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }])
    const result = { pending: 0, approved: 0, rejected: 0, total: 0 }
    counts.forEach(item => {
      result[item._id] = item.count
      result.total += item.count
    })
    res.status(200).json(result)
  } catch (error) {
    console.error('Error fetching application counts:', error)
    res.status(500).json({ message: 'Server error' })
  }
}

app.get('/admin/mentor-applications/counts', requireAuth, requireAdmin, handleGetMentorApplicationCounts)
app.get('/api/admin/mentor-applications/counts', requireAuth, requireAdmin, handleGetMentorApplicationCounts)

const handleUpdateMentorApplicationStatus = async (req, res) => {
  const session = await mongoose.startSession()
  session.startTransaction()
  try {
    const { id } = req.params
    const { status } = req.body
    if (!['approved', 'rejected', 'pending'].includes(status)) {
      await session.abortTransaction()
      session.endSession()
      return res.status(400).json({ message: 'Invalid status' })
    }
    const application = await MentorApplication.findById(id).session(session)
    if (!application) {
      await session.abortTransaction()
      session.endSession()
      return res.status(404).json({ message: 'Application not found' })
    }
    const user = await User.findById(application.userId).session(session)
    if (!user) {
      await session.abortTransaction()
      session.endSession()
      return res.status(404).json({ message: 'User not found' })
    }
    application.status = status
    await application.save({ session })
    if (status === 'approved') {
      user.role = 'mentor'
      await user.save({ session })
      await Notification.create([{ userId: user._id, title: 'Mentor Application Approved! 🎉', message: 'Congratulations! Your mentor application has been approved. You can now start hosting paid sessions.', type: 'mentor_approved' }], { session })
    } else if (status === 'rejected') {
      await Notification.create([{ userId: user._id, title: 'Mentor Application Update', message: 'Your mentor application has been reviewed. Please check your application details and reapply if needed.', type: 'mentor_rejected' }], { session })
    }
    await session.commitTransaction()
    session.endSession()
    const response = { ...application.toObject(), user: { _id: user._id, firstName: user.firstName, lastName: user.lastName, email: user.email, role: user.role } }
    res.status(200).json(response)
  } catch (error) {
    console.error('Error updating mentor application status:', error)
    return res.status(500).json({ message: 'Server error' })
  }
}

app.put('/admin/mentor-applications/:id/status', requireAuth, requireAdmin, handleUpdateMentorApplicationStatus)
app.put('/api/admin/mentor-applications/:id/status', requireAuth, requireAdmin, handleUpdateMentorApplicationStatus)

// Mentor application (create/update)
app.post('/api/mentor-applications', async (req, res) => {
  try {
    let userId = req.session?.user?.id
    if (!userId) {
      const { email, password } = req.body || {}
      if (email && password) {
        const authUser = await User.findOne({ email })
        if (!authUser) return res.status(401).json({ message: 'Invalid credentials' })
        const ok = await bcrypt.compare(String(password), authUser.password)
        if (!ok) return res.status(401).json({ message: 'Invalid credentials' })
        req.session.user = { id: authUser._id, email: authUser.email, role: authUser.role }
        userId = String(authUser._id)
      } else {
        return res.status(401).json({ message: 'Unauthorized' })
      }
    }
    const { phoneNumber, bio, domain, linkedin, portfolio } = req.body || {}
    const auth = await User.findById(userId)
    if (!auth) return res.status(404).json({ message: 'User not found' })
    const fullName = `${auth.firstName} ${auth.lastName}`.trim()
    const application = await MentorApplication.findOneAndUpdate(
      { userId },
      { name: fullName, phoneNumber, bio, domain, linkedin, portfolio, applicationDate: new Date(), status: 'pending' },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    )
    return res.status(200).json(application)
  } catch (error) {
    console.error('Error creating mentor application:', error)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Notifications
app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id
    const notifications = await Notification.find({ userId }).sort({ createdAt: -1 }).limit(50)
    res.status(200).json(notifications)
  } catch (error) {
    console.error('Error fetching notifications:', error)
    res.status(500).json({ message: 'Server error' })
  }
})

app.put('/api/notifications/:id/read', requireAuth, async (req, res) => {
  try {
    const { id } = req.params
    const userId = req.session.user.id
    const notification = await Notification.findOneAndUpdate({ _id: id, userId }, { isRead: true, readAt: new Date() }, { new: true })
    if (!notification) return res.status(404).json({ message: 'Notification not found' })
    res.status(200).json(notification)
  } catch (error) {
    console.error('Error marking notification as read:', error)
    res.status(500).json({ message: 'Server error' })
  }
})

app.put('/api/notifications/read-all', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id
    await Notification.updateMany({ userId, isRead: false }, { isRead: true, readAt: new Date() })
    res.status(200).json({ message: 'All notifications marked as read' })
  } catch (error) {
    console.error('Error marking all notifications as read:', error)
    res.status(500).json({ message: 'Server error' })
  }
})

// Mentor status
app.get('/api/mentor-status', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id
    const application = await MentorApplication.findOne({ userId })
    res.status(200).json({ hasApplication: !!application, status: application?.status || null, applicationDate: application?.applicationDate || null })
  } catch (error) {
    console.error('Error checking mentor status:', error)
    res.status(500).json({ message: 'Server error' })
  }
})

// Admin - users
const handleGetUsers = async (req, res) => {
  try {
    const users = await User.find({}, 'firstName lastName email role field bio createdAt isBlocked').sort({ createdAt: -1 })
    res.status(200).json(users)
  } catch (error) {
    console.error('Error fetching users:', error)
    res.status(500).json({ message: 'Server error' })
  }
}

app.get('/admin/users', requireAuth, requireAdmin, handleGetUsers)
app.get('/api/admin/users', requireAuth, requireAdmin, handleGetUsers)

const handleUpdateUserStatus = async (req, res) => {
  try {
    const { id } = req.params
    const { isBlocked } = req.body
    const user = await User.findByIdAndUpdate(id, { isBlocked }, { new: true })
    if (!user) return res.status(404).json({ message: 'User not found' })
    res.status(200).json(user)
  } catch (error) {
    console.error('Error updating user status:', error)
    res.status(500).json({ message: 'Server error' })
  }
}

app.put('/admin/users/:id/status', requireAuth, requireAdmin, handleUpdateUserStatus)
app.put('/api/admin/users/:id/status', requireAuth, requireAdmin, handleUpdateUserStatus)

const handleDeleteUser = async (req, res) => {
  try {
    const { id } = req.params
    const user = await User.findByIdAndDelete(id)
    if (!user) return res.status(404).json({ message: 'User not found' })
    await MentorApplication.deleteMany({ userId: id })
    res.status(200).json({ message: 'User deleted successfully' })
  } catch (error) {
    console.error('Error deleting user:', error)
    res.status(500).json({ message: 'Server error' })
  }
}

app.delete('/admin/users/:id', requireAuth, requireAdmin, handleDeleteUser)
app.delete('/api/admin/users/:id', requireAuth, requireAdmin, handleDeleteUser)

// Admin - sessions overview (mentor availability + booked sessions)
const handleGetAdminSessions = async (req, res) => {
  try {
    const now = new Date()

    const slots = await Slot.find({})
      .populate('mentorId', 'firstName lastName email')
      .sort({ start: -1 })
      .lean()

    const slotIds = slots.map(s => s._id).filter(Boolean)
    const bookings = slotIds.length
      ? await Booking.find({ slotId: { $in: slotIds } })
          .populate('userId', 'firstName lastName email')
          .populate('mentorId', 'firstName lastName email')
          .lean()
      : []

    const bookingBySlotId = new Map()
    for (const b of bookings) bookingBySlotId.set(String(b.slotId), b)

    const sessions = slots.map(slot => {
      const booking = bookingBySlotId.get(String(slot._id)) || null
      const start = slot?.start ? new Date(slot.start) : null
      const end = slot?.end
        ? new Date(slot.end)
        : (slot?.durationMinutes && start ? new Date(start.getTime() + Number(slot.durationMinutes) * 60000) : null)

      const endedByTime = end ? end < now : (start ? start < now : false)
      const bookingStatus = booking?.status || 'available'

      let sessionState = 'available'
      if (booking) {
        if (bookingStatus === 'cancelled') sessionState = 'cancelled'
        else if (bookingStatus === 'completed' || endedByTime) sessionState = 'completed'
        else sessionState = 'upcoming'
      }

      const mentorObj = slot.mentorId && typeof slot.mentorId === 'object' ? slot.mentorId : {}
      const menteeObj = booking?.userId && typeof booking.userId === 'object' ? booking.userId : {}

      return {
        id: String(slot._id),
        slotId: String(slot._id),
        bookingId: booking ? String(booking._id) : null,
        mentor: {
          id: mentorObj?._id ? String(mentorObj._id) : (slot.mentorId ? String(slot.mentorId) : ''),
          name: `${mentorObj?.firstName || ''} ${mentorObj?.lastName || ''}`.trim() || 'Unknown mentor',
          email: mentorObj?.email || ''
        },
        mentee: booking ? {
          id: menteeObj?._id ? String(menteeObj._id) : (booking.userId ? String(booking.userId) : ''),
          name: `${menteeObj?.firstName || ''} ${menteeObj?.lastName || ''}`.trim() || 'Unknown mentee',
          email: menteeObj?.email || ''
        } : null,
        start,
        end,
        date: start ? start.toISOString() : null,
        durationMinutes: slot?.durationMinutes || (start && end ? Math.max(1, Math.round((end - start) / 60000)) : null),
        price: Number(slot?.price || 0),
        label: slot?.label || '',
        isBooked: !!booking,
        bookingStatus,
        sessionState,
        sessionEnded: booking ? (sessionState === 'completed') : false,
        notes: booking?.notes || ''
      }
    })

    const grouped = {
      upcoming: sessions.filter(s => s.sessionState === 'upcoming'),
      completed: sessions.filter(s => s.sessionState === 'completed'),
      cancelled: sessions.filter(s => s.sessionState === 'cancelled'),
      available: sessions.filter(s => s.sessionState === 'available')
    }

    return res.status(200).json({
      sessions,
      ...grouped,
      counts: {
        total: sessions.length,
        booked: sessions.filter(s => s.isBooked).length,
        available: grouped.available.length,
        upcoming: grouped.upcoming.length,
        completed: grouped.completed.length,
        cancelled: grouped.cancelled.length
      }
    })
  } catch (error) {
    console.error('Error fetching admin sessions:', error)
    return res.status(500).json({ message: 'Server error' })
  }
}

app.get('/admin/sessions', requireAuth, requireAdmin, handleGetAdminSessions)
app.get('/api/admin/sessions', requireAuth, requireAdmin, handleGetAdminSessions)

// Slots API
app.get('/api/slots', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id
    const slots = await Slot.find({ mentorId: userId }).sort({ start: 1 })
    res.status(200).json(slots)
  } catch (err) {
    console.error('Error fetching slots:', err)
    res.status(500).json({ message: 'Server error' })
  }
})

app.post('/api/slots', requireAuth, async (req, res) => {
  try {
    // Helpful guard: detect when caller sent admin/mentor-application payload by mistake
    // (e.g. status/email/password) instead of slot data (expects "start").
    const body = req.body || {};
    const looksLikeAdminAction = typeof body.status !== 'undefined' || (body.email && body.password);
    const hasStart = typeof body.start !== 'undefined';

    if (looksLikeAdminAction && !hasStart) {
      return res.status(400).json({
        message: 'Your request looks like an admin/mentor-application request, not a slot creation.',
        hint: 'To update mentor application status: PUT /api/admin/mentor-applications/:id/status (body: { "status":"approved" }).\n' +
              'To create a mentor application: POST /api/mentor-applications (include phoneNumber/bio etc.).\n' +
              'To create a slot (this endpoint) send JSON with "start" (ISO datetime) and optional "durationMinutes"/"end"/"price".'
      });
    }

    const userId = req.session.user.id
    const { start, end, durationMinutes, price, label } = req.body
    if (!start) return res.status(400).json({ message: 'start datetime is required' })
    const startDate = new Date(start)
    if (isNaN(startDate)) return res.status(400).json({ message: 'Invalid start datetime' })
    let endDate = null
    if (end) {
      endDate = new Date(end)
      if (isNaN(endDate)) return res.status(400).json({ message: 'Invalid end datetime' })
    } else if (durationMinutes) {
      endDate = new Date(startDate.getTime() + Number(durationMinutes) * 60000)
    }
    const created = await Slot.create({ mentorId: userId, start: startDate, end: endDate, durationMinutes: durationMinutes ? Number(durationMinutes) : undefined, price: price ? Number(price) : 0, label: label || '' })
    res.status(201).json(created)
  } catch (err) {
    console.error('Error creating slot:', err)
    res.status(500).json({ message: 'Server error' })
  }
})

app.put('/api/slots/:id', requireAuth, async (req, res) => {
  try {
    // Helpful guard: detect when caller sends admin/mentor-application payload by mistake
    // (e.g. status/email/password) instead of slot update data (expects "start" or slot fields).
    const body = req.body || {};
    const looksLikeAdminAction = typeof body.status !== 'undefined' || (body.email && body.password);
    const hasSlotFields = typeof body.start !== 'undefined' || typeof body.end !== 'undefined' || typeof body.durationMinutes !== 'undefined' || typeof body.price !== 'undefined' || typeof body.label !== 'undefined';

    if (looksLikeAdminAction && !hasSlotFields) {
      return res.status(400).json({
        message: 'Request payload does not look like a slot update.',
        hint: 'To update mentor application status use: PUT /api/admin/mentor-applications/:id/status with body { "status":"approved" } (or login first). To update a slot send fields like "start","end","durationMinutes","price".'
      });
    }

    const userId = req.session.user.id;
    const { id } = req.params;
    const { start, end, durationMinutes, price, label } = req.body;

    const slot = await Slot.findById(id);
    if (!slot) return res.status(404).json({ message: 'Slot not found' });
    if (String(slot.mentorId) !== String(userId)) return res.status(403).json({ message: 'Forbidden' });

    if (start) {
      const s = new Date(start);
      if (isNaN(s)) return res.status(400).json({ message: 'Invalid start datetime' });
      slot.start = s;
    }
    if (end) {
      const e = new Date(end);
      if (isNaN(e)) return res.status(400).json({ message: 'Invalid end datetime' });
      slot.end = e;
    } else if (durationMinutes) {
      slot.durationMinutes = Number(durationMinutes);
      slot.end = new Date(new Date(slot.start).getTime() + Number(durationMinutes) * 60000);
    }
    if (price !== undefined) slot.price = Number(price);
    if (label !== undefined) slot.label = label;

    await slot.save();
    return res.status(200).json(slot);
  } catch (err) {
    console.error('Error updating slot:', err);
    return res.status(500).json({ message: 'Server error' });
  }
})

app.delete('/api/slots/:id', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id
    const { id } = req.params
    const slot = await Slot.findById(id)
    if (!slot) return res.status(404).json({ message: 'Slot not found' })
    if (String(slot.mentorId) !== String(userId)) return res.status(403).json({ message: 'Forbidden' })
    await Slot.findByIdAndDelete(id)
    res.status(200).json({ message: 'Slot deleted' })
  } catch (err) {
    console.error('Error deleting slot:', err)
    res.status(500).json({ message: 'Server error' })
  }
})

// Bookings API
app.post('/api/bookings', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id
    const { slotId, notes } = req.body
    if (!slotId) return res.status(400).json({ message: 'slotId is required' })
    const slot = await Slot.findById(slotId)
    if (!slot) return res.status(404).json({ message: 'Slot not found' })
    const existingBooking = await Booking.findOne({ slotId })
    if (existingBooking) return res.status(409).json({ message: 'Slot already booked' })
    if (String(slot.mentorId) === String(userId)) return res.status(400).json({ message: 'Cannot book your own slot' })
    const booking = await Booking.create({ userId, slotId, mentorId: slot.mentorId, notes: notes || '', status: 'confirmed' })
    const populatedBooking = await Booking.findById(booking._id).populate('userId', 'firstName lastName email').populate('mentorId', 'firstName lastName email').populate('slotId')
    res.status(201).json(populatedBooking)
  } catch (err) {
    console.error('Error creating booking:', err)
    res.status(500).json({ message: 'Server error' })
  }
})

app.get('/api/bookings', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id
    const bookings = await Booking.find({ userId }).populate('mentorId', 'firstName lastName email profileImage title').populate('slotId').sort({ createdAt: -1 })
    res.status(200).json(bookings)
  } catch (err) {
    console.error('Error fetching bookings:', err)
    res.status(500).json({ message: 'Server error' })
  }
})

app.get('/api/mentor/bookings', requireAuth, async (req, res) => {
  try {
    const mentorId = req.session.user.id
    const bookings = await Booking.find({ mentorId }).populate('userId', 'firstName lastName email profileImage').populate('slotId').sort({ createdAt: -1 })
    res.status(200).json(bookings)
  } catch (err) {
    console.error('Error fetching mentor bookings:', err)
    res.status(500).json({ message: 'Server error' })
  }
})

app.put('/api/bookings/:id', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id
    const { id } = req.params
    const { status, meetingLink } = req.body
    const booking = await Booking.findById(id)
    if (!booking) return res.status(404).json({ message: 'Booking not found' })
    if (String(booking.mentorId) !== String(userId) && String(booking.userId) !== String(userId)) return res.status(403).json({ message: 'Forbidden' })
    if (status) booking.status = status
    if (meetingLink !== undefined) booking.meetingLink = meetingLink
    await booking.save()
    const populatedBooking = await Booking.findById(booking._id).populate('userId', 'firstName lastName email').populate('mentorId', 'firstName lastName email').populate('slotId')
    res.status(200).json(populatedBooking)
  } catch (err) {
    console.error('Error updating booking:', err)
    res.status(500).json({ message: 'Server error' })
  }
})

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Session destruction error:', err)
      return res.status(500).json({ message: 'Could not log out' })
    }
    res.clearCookie('connect.sid')
    res.status(200).json({ message: 'Logged out successfully' })
  })
})

const BASE_PORT = Number(process.env.PORT) || 3000
if (!process.env.VERCEL) {
  const tryListen = (p) => {
    const server = app.listen(p, () => {
      console.log(`Server running on port ${p}`)
    })
    server.on('error', err => {
      if (err && err.code === 'EADDRINUSE') {
        tryListen(p + 1)
      } else {
        throw err
      }
    })
  }
  tryListen(BASE_PORT)
}

export default app
