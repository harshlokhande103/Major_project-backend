import express from 'express'
import mongoose from 'mongoose'
import cors from 'cors'
import dotenv from 'dotenv'
import multer from 'multer'
import { v2 as cloudinary } from 'cloudinary'
import path from 'path'
import fs from 'fs'
import bcrypt from 'bcryptjs'
import helmet from 'helmet'
import session from 'express-session'
import MongoStore from 'connect-mongo'
import cookieParser from 'cookie-parser'
import rateLimit from 'express-rate-limit'
import MentorApplication from './models/MentorApplication.js'
import Notification from './models/Notification.js'
import Slot from './models/Slot.js' // <-- added import (keep near other model imports)
import Booking from './models/Booking.js'
import isAdmin from './middleware/isAdmin.js'
import pagesRouter from './routes/pages.js'
import chatRouter from './routes/chat.js'

// Load environment variables
dotenv.config()

// Initialize Express app
const app = express()

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}))
app.use(express.json())
app.use(cookieParser())

// Trust proxy when behind a reverse proxy (Render, Heroku, etc.) so secure cookies and client IPs work
// Render sets env RENDER=true; we can also just always trust first proxy safely in this deployment
app.set('trust proxy', 1)

// CORS (allow local dev and deployed frontend with credentials)
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
// Explicitly handle preflight for all routes
app.options('*', cors(corsOptions))

// Session configuration (Mongo-backed for serverless)
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
      ttl: 60 * 60 * 8 // 8 hours in seconds
    }),
    cookie: {
      httpOnly: true,
      // For local dev with Vite proxy (same-origin), use non-secure and SameSite=Lax
      // For production/serverless (cross-site), use Secure + SameSite=None
      secure: !!process.env.VERCEL || process.env.NODE_ENV === 'production',
      sameSite: (!!process.env.VERCEL || process.env.NODE_ENV === 'production') ? 'none' : 'lax',
      // domain: process.env.SESSION_COOKIE_DOMAIN || undefined,
      maxAge: 1000 * 60 * 60 * 8
    }
  })
)

// Static files
// Static files for uploads will be registered after multer setup so we can reuse the same uploadsDir

// Add a flag to indicate DB connection state
let mongoConnected = false;

// Lightweight health check for Postman — now returns DB state too
app.get('/api/health', (req, res) => {
  res.status(200).json({ ok: true, mongoConnected });
})

// Database connection
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/Clarity_Call'
if (process.env.NODE_ENV === 'production' && !process.env.MONGODB_URI) {
  console.error('MONGODB_URI must be set in production')
}

mongoose.set('strictQuery', true)
mongoose
  .connect(mongoUri)
  .then(() => {
    console.log('MongoDB connected');
    mongoConnected = true;
  })
  .catch(err => {
    // Log but DO NOT exit in serverless (Vercel) — exiting causes FUNCTION_INVOCATION_FAILED
    console.error('MongoDB connection error:', err);
    // process.exit(1) <-- removed so functions don't crash when DB is unreachable
  })

// Register mentor routes
import mentorRouter from './routes/mentor.js';
app.use('/api/mentors', mentorRouter);

// Register pages router under /api/pages so requests like /api/pages/home work on Vercel
app.use('/api/pages', pagesRouter);
// (optional) keep old mount for direct server usage:
// app.use('/pages', pagesRouter);

// User Schema


const userSchema = new mongoose.Schema({
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

// File upload configuration -> store in MongoDB (no filesystem)
const storage = multer.memoryStorage()
const upload = multer({ storage })

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
})

// Routes
// Configure Cloudinary if available (used in production for persistence)
if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  })
}

app.post('/api/register', authLimiter, upload.single('profileImage'), async (req, res) => {
  try {
    // Accept both JSON and form-data. Multer populated req.file when form-data is used.
    // Extract fields; support a single "name" that will be split into first/last.
    let {
      firstName,
      lastName,
      name,
      email,
      password,
      bio,
      title,
      field,
      expertise
    } = req.body || {};

    // If caller provided "name" (single field), split into first/last
    if ((!firstName || !lastName) && name && typeof name === 'string') {
      const parts = name.trim().split(/\s+/);
      if (!firstName) firstName = parts.shift() || '';
      if (!lastName) lastName = parts.join(' ') || lastName || '';
    }

    // Normalize strings
    firstName = firstName ? String(firstName).trim() : '';
    lastName  = lastName ? String(lastName).trim() : '';
    email     = email ? String(email).trim().toLowerCase() : '';
    password  = password ? String(password) : '';

    // Validate required fields and report which are missing
    const required = { firstName, lastName, email, password };
    const missing = Object.keys(required).filter(k => !required[k]);
    if (missing.length > 0) {
      return res.status(400).json({
        message: 'Missing required fields',
        missing
      });
    }

    // Protect: basic email format check (optional)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    // Prevent duplicate registration
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Ensure expertise is an array if provided as CSV string
    let expertiseArr = [];
    if (Array.isArray(expertise)) {
      expertiseArr = expertise;
    } else if (typeof expertise === 'string' && expertise.trim() !== '') {
      expertiseArr = expertise.split(',').map(s => s.trim()).filter(Boolean);
    }

    // Create user record
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
    });

    // If multipart upload provided a file, save it into DB and expose avatar URL
    if (req.file && req.file.buffer) {
      user.profileImageData = req.file.buffer;
      user.profileImageContentType = req.file.mimetype || 'application/octet-stream';
      user.profileImage = `/api/users/${user._id}/avatar`;
      await user.save();
    }

    // Return created user (omit password)
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
    };

    return res.status(201).json(safe);
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
})

app.get('/', (req, res) => {
  res.send('Welcome to the Backend API!')
})

// API Routes
app.use('/pages', pagesRouter)
app.use('/api/chat', chatRouter)
app.post('/api/users/:id/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const { id } = req.params;

    // If caller used the literal placeholder like ":id" try to resolve from session
    let targetUserId = id;
    if (typeof id === 'string' && id.startsWith(':')) {
      if (req.session?.user?.id) {
        targetUserId = String(req.session.user.id);
      } else {
        return res.status(400).json({
          message: 'Invalid user id — replace ":id" with a real MongoDB ObjectId, or authenticate first so the server can use your session id.'
        });
      }
    }

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(String(targetUserId))) {
      return res.status(400).json({ message: 'Invalid user id' });
    }

    const user = await User.findById(targetUserId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // 1) Multipart upload handling (preferred)
    if (req.file && req.file.buffer) {
      user.profileImageData = req.file.buffer;
      user.profileImageContentType = req.file.mimetype || 'application/octet-stream';
      user.profileImage = `/api/users/${user._id}/avatar`;
      await user.save();

      return res.status(200).json({
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        profileImage: user.profileImage
      });
    }

    // 2) JSON base64 fallback
    if (req.is('application/json') && (req.body && (req.body.base64 || req.body.dataUrl || req.body.file))) {
      let base64 = req.body.base64 || '';
      let contentType = req.body.contentType || 'application/octet-stream';
      if (!base64 && req.body.dataUrl) {
        const m = String(req.body.dataUrl).match(/^data:([^;]+);base64,(.*)$/);
        if (m) {
          contentType = m[1];
          base64 = m[2];
        }
      }
      if (!base64 && req.body.file && typeof req.body.file === 'string') {
        base64 = req.body.file;
      }
      if (!base64) {
        return res.status(400).json({ message: 'No file uploaded. Provide multipart/form-data (key "avatar") or JSON { base64: "...", contentType: "image/png" }' });
      }
      const buffer = Buffer.from(base64, 'base64');
      user.profileImageData = buffer;
      user.profileImageContentType = contentType;
      user.profileImage = `/api/users/${user._id}/avatar`;
      await user.save();

      return res.status(200).json({
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        profileImage: user.profileImage
      });
    }

    // Nothing usable found in request
    return res.status(400).json({ message: 'No file uploaded. Use multipart/form-data (key "avatar") or JSON base64 payload.' });
  } catch (err) {
    console.error('Avatar upload error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
})

// Serve user avatar from MongoDB
app.get('/api/users/:id/avatar', async (req, res) => {
  try {
    const { id } = req.params
    const user = await User.findById(id).select('profileImageData profileImageContentType')
    if (!user || !user.profileImageData) {
      return res.status(404).json({ message: 'Avatar not found' })
    }
    res.setHeader('Content-Type', user.profileImageContentType || 'application/octet-stream')
    return res.status(200).send(user.profileImageData)
  } catch (err) {
    console.error('Avatar fetch error', err)
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
      profileImage: user.profileImage,
      bio: user.bio,
      title: user.title,
      field: user.field,
      expertise: user.expertise,
      role: user.role
    })

  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Get user profile
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id
    const user = await User.findById(userId).select('-password')
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' })
    }
    
    return res.status(200).json(user)
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Public: list users (limited fields)
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({}, 'firstName lastName email profileImage role field bio').lean()
    return res.status(200).json(Array.isArray(users) ? users : [])
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Public: get user by id (without password)
app.get('/api/user/:id', async (req, res) => {
  try {
    let { id } = req.params;

    // If caller used the literal placeholder like "/api/user/:id", redirect them
    // to the users list so they can pick a real ObjectId. This prevents 400 responses
    // when testing with the placeholder in tools like Postman.
    if (typeof id === 'string' && id.startsWith(':')) {
      return res.redirect(302, '/api/users');
    }

    // Validate ObjectId early and return a clear error
    if (!mongoose.Types.ObjectId.isValid(String(id))) {
      return res.status(400).json({ message: 'Invalid user id' });
    }

    const user = await User.findById(id).select('-password').lean();
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.status(200).json(user);
  } catch (err) {
    console.error('GET /api/user/:id error', err);
    return res.status(500).json({ message: 'Server error' });
  }
})

// Profile update
app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    const { id, firstName, lastName, title, bio, expertise, field } = req.body

    const user = await User.findById(id)
    if (!user) {
      return res.status(404).json({ message: 'User not found' })
    }

    user.firstName = firstName
    user.lastName = lastName
    user.title = title
    user.bio = bio
    user.field = field
    user.expertise = expertise

    await user.save()
    
    return res.status(200).json(user)
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

// Admin - Get all mentor applications with optional status filter
const handleGetMentorApplications = async (req, res) => {
  try {
    const { status } = req.query;
    let filter = {};
    
    if (status && ['pending', 'approved', 'rejected'].includes(status)) {
      filter.status = status;
    }
    
    const applications = await MentorApplication.find(filter).populate('userId', 'firstName lastName email');
    res.status(200).json(applications);
  } catch (error) {
    console.error('Error fetching mentor applications:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

app.get('/admin/mentor-applications', requireAuth, isAdmin, handleGetMentorApplications);
app.get('/api/admin/mentor-applications', requireAuth, isAdmin, handleGetMentorApplications);

// Admin - Get application counts by status
const handleGetMentorApplicationCounts = async (req, res) => {
  try {
    const counts = await MentorApplication.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);
    
    const result = {
      pending: 0,
      approved: 0,
      rejected: 0,
      total: 0
    };
    
    counts.forEach(item => {
      result[item._id] = item.count;
      result.total += item.count;
    });
    
    res.status(200).json(result);
  } catch (error) {
    console.error('Error fetching application counts:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

app.get('/admin/mentor-applications/counts', requireAuth, isAdmin, handleGetMentorApplicationCounts);
app.get('/api/admin/mentor-applications/counts', requireAuth, isAdmin, handleGetMentorApplicationCounts);

// Admin - Update mentor application status
const handleUpdateMentorApplicationStatus = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!['approved', 'rejected', 'pending'].includes(status)) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Invalid status' });
    }

    // First, find the application with user details
    const application = await MentorApplication.findById(id).session(session);
    if (!application) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'Application not found' });
    }

    // Get the user to be updated
    const user = await User.findById(application.userId).session(session);
    if (!user) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'User not found' });
    }

    // Update application status
    application.status = status;
    await application.save({ session });

    let updatedUser = user;
    // If approved, update user role to mentor
    if (status === 'approved') {
      user.role = 'mentor';
      updatedUser = await user.save({ session });
      
      // Create notification for mentor
      await Notification.create([{
        userId: user._id,
        title: 'Mentor Application Approved! 🎉',
        message: 'Congratulations! Your mentor application has been approved. You can now start hosting paid sessions.',
        type: 'mentor_approved'
      }], { session });
    } else if (status === 'rejected') {
      // Create notification for rejection
      await Notification.create([{
        userId: user._id,
        title: 'Mentor Application Update',
        message: 'Your mentor application has been reviewed. Please check your application details and reapply if needed.',
        type: 'mentor_rejected'
      }], { session });
    }

    // Commit the transaction
    await session.commitTransaction();
    session.endSession();

    // Populate the response with user details
    const response = {
      ...application.toObject(),
      user: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role
      }
    };

    res.status(200).json(response);
  } catch (error) {
    console.error('Error updating mentor application status:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

app.put('/admin/mentor-applications/:id/status', requireAuth, isAdmin, handleUpdateMentorApplicationStatus);
app.put('/api/admin/mentor-applications/:id/status', requireAuth, isAdmin, handleUpdateMentorApplicationStatus);

// Mentor - Create or update an application
app.post('/api/mentor-applications', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { phoneNumber, bio, domain, linkedin, portfolio } = req.body;
    
    // Get the authenticated user's information
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Use the user's first and last name from their profile
    const fullName = `${user.firstName} ${user.lastName}`.trim();

    // Upsert: create new or update existing application for this user
    const application = await MentorApplication.findOneAndUpdate(
      { userId },
      { 
        name: fullName, // Use the name from user's profile, not from request
        phoneNumber, 
        bio, 
        domain, 
        linkedin, 
        portfolio, 
        applicationDate: new Date(), 
        status: 'pending' 
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    return res.status(200).json(application);
  } catch (error) {
    console.error('Error creating mentor application:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Get user notifications
app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.status(200).json(notifications);
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Mark notification as read
app.put('/api/notifications/:id/read', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.session.user.id;
    
    const notification = await Notification.findOneAndUpdate(
      { _id: id, userId },
      { isRead: true, readAt: new Date() },
      { new: true }
    );
    
    if (!notification) {
      return res.status(404).json({ message: 'Notification not found' });
    }
    
    res.status(200).json(notification);
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Mark all notifications as read
app.put('/api/notifications/read-all', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    
    await Notification.updateMany(
      { userId, isRead: false },
      { isRead: true, readAt: new Date() }
    );
    
    res.status(200).json({ message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Check mentor application status
app.get('/api/mentor-status', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const application = await MentorApplication.findOne({ userId });
    
    res.status(200).json({
      hasApplication: !!application,
      status: application?.status || null,
      applicationDate: application?.applicationDate || null
    });
  } catch (error) {
    console.error('Error checking mentor status:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin - Get all users
const handleGetUsers = async (req, res) => {
  try {
    const users = await User.find({}, 'firstName lastName email role field bio createdAt isBlocked')
      .sort({ createdAt: -1 });
    res.status(200).json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

app.get('/admin/users', requireAuth, isAdmin, handleGetUsers);
app.get('/api/admin/users', requireAuth, isAdmin, handleGetUsers);

// Admin - Update user status (block/unblock)
const handleUpdateUserStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { isBlocked } = req.body;
    
    const user = await User.findByIdAndUpdate(
      id, 
      { isBlocked }, 
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.status(200).json(user);
  } catch (error) {
    console.error('Error updating user status:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

app.put('/admin/users/:id/status', requireAuth, isAdmin, handleUpdateUserStatus);
app.put('/api/admin/users/:id/status', requireAuth, isAdmin, handleUpdateUserStatus);

// Admin - Delete user
const handleDeleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    
    const user = await User.findByIdAndDelete(id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Also delete related mentor applications
    await MentorApplication.deleteMany({ userId: id });
    
    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

app.delete('/admin/users/:id', requireAuth, isAdmin, handleDeleteUser);
app.delete('/api/admin/users/:id', requireAuth, isAdmin, handleDeleteUser);

// -------------------- Slots API for mentors --------------------
// Get all slots for current authenticated mentor
app.get('/api/slots', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const slots = await Slot.find({ mentorId: userId }).sort({ start: 1 });
    res.status(200).json(slots);
  } catch (err) {
    console.error('Error fetching slots:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create a slot
app.post('/api/slots', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { start, end, durationMinutes, price, label } = req.body;

    if (!start) return res.status(400).json({ message: 'start datetime is required' });

    const startDate = new Date(start);
    if (isNaN(startDate)) return res.status(400).json({ message: 'Invalid start datetime' });

    let endDate = null;
    if (end) {
      endDate = new Date(end);
      if (isNaN(endDate)) return res.status(400).json({ message: 'Invalid end datetime' });
    } else if (durationMinutes) {
      endDate = new Date(startDate.getTime() + Number(durationMinutes) * 60000);
    }

    const created = await Slot.create({
      mentorId: userId,
      start: startDate,
      end: endDate,
      durationMinutes: durationMinutes ? Number(durationMinutes) : undefined,
      price: price ? Number(price) : 0,
      label: label || ''
    });

    res.status(201).json(created);
  } catch (err) {
    console.error('Error creating slot:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update slot (only owner)
app.put('/api/slots/:id', requireAuth, async (req, res) => {
  try {
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
    res.status(200).json(slot);
  } catch (err) {
    console.error('Error updating slot:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete slot (only owner)
app.delete('/api/slots/:id', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { id } = req.params;
    const slot = await Slot.findById(id);
    if (!slot) return res.status(404).json({ message: 'Slot not found' });
    if (String(slot.mentorId) !== String(userId)) return res.status(403).json({ message: 'Forbidden' });

    await Slot.findByIdAndDelete(id);
    res.status(200).json({ message: 'Slot deleted' });
  } catch (err) {
    console.error('Error deleting slot:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Session destruction error:', err);
      return res.status(500).json({ message: 'Could not log out' });
    }
    res.clearCookie('connect.sid');
    res.status(200).json({ message: 'Logged out successfully' });
  });
});

// Public: Get slots for a mentor (no auth required)
app.get('/api/mentors/:id/slots', async (req, res) => {
  try {
    const mentorId = req.params.id;
    if (!mentorId) return res.status(400).json({ message: 'mentor id required' });

    // Find slots for the given mentor (only public fields)
    const slots = await Slot.find({ mentorId }).sort({ start: 1 }).select('start end durationMinutes price label');

    // Normalize to plain array
    res.status(200).json(slots);
  } catch (err) {
    console.error('Error fetching mentor slots:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// -------------------- Bookings API --------------------
// Create a booking
app.post('/api/bookings', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { slotId, notes } = req.body;

    if (!slotId) return res.status(400).json({ message: 'slotId is required' });

    // Find the slot and ensure it exists
    const slot = await Slot.findById(slotId);
    if (!slot) return res.status(404).json({ message: 'Slot not found' });

    // Check if slot is already booked
    const existingBooking = await Booking.findOne({ slotId });
    if (existingBooking) return res.status(409).json({ message: 'Slot already booked' });

    // Prevent booking own slots
    if (String(slot.mentorId) === String(userId)) {
      return res.status(400).json({ message: 'Cannot book your own slot' });
    }

    // Create booking
    const booking = await Booking.create({
      userId,
      slotId,
      mentorId: slot.mentorId,
      notes: notes || '',
      status: 'confirmed'
    });

    // Populate booking details for response
    const populatedBooking = await Booking.findById(booking._id)
      .populate('userId', 'firstName lastName email')
      .populate('mentorId', 'firstName lastName email')
      .populate('slotId');

    res.status(201).json(populatedBooking);
  } catch (err) {
    console.error('Error creating booking:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's bookings
app.get('/api/bookings', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const bookings = await Booking.find({ userId })
      .populate('mentorId', 'firstName lastName email profileImage title')
      .populate('slotId')
      .sort({ createdAt: -1 });

    res.status(200).json(bookings);
  } catch (err) {
    console.error('Error fetching bookings:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get mentor's bookings (for mentors to see their booked sessions)
app.get('/api/mentor/bookings', requireAuth, async (req, res) => {
  try {
    const mentorId = req.session.user.id;
    const bookings = await Booking.find({ mentorId })
      .populate('userId', 'firstName lastName email profileImage')
      .populate('slotId')
      .sort({ createdAt: -1 });

    res.status(200).json(bookings);
  } catch (err) {
    console.error('Error fetching mentor bookings:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update booking status (mentor can cancel, complete, etc.)
app.put('/api/bookings/:id', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { id } = req.params;
    const { status, meetingLink } = req.body;

    const booking = await Booking.findById(id);
    if (!booking) return res.status(404).json({ message: 'Booking not found' });

    // Only mentor or the user who booked can update
    if (String(booking.mentorId) !== String(userId) && String(booking.userId) !== String(userId)) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    // Update fields
    if (status) booking.status = status;
    if (meetingLink !== undefined) booking.meetingLink = meetingLink;

    await booking.save();

    // Populate for response
    const populatedBooking = await Booking.findById(booking._id)
      .populate('userId', 'firstName lastName email')
      .populate('mentorId', 'firstName lastName email')
      .populate('slotId');

    res.status(200).json(populatedBooking);
  } catch (err) {
    console.error('Error updating booking:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start server (local dev only). On Vercel, export the app for serverless.
const PORT = process.env.PORT || 3000
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
  })
}

export default app
