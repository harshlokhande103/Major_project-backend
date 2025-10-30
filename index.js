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
import cookieParser from 'cookie-parser'
import rateLimit from 'express-rate-limit'
import MentorApplication from './models/MentorApplication.js'
import Notification from './models/Notification.js'
import isAdmin from './middleware/isAdmin.js'
import pagesRouter from './routes/pages.js'

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

// Trust proxy when behind a reverse proxy (Render, Heroku, etc.) so secure cookies work
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1)
}

// CORS (single source of truth)
// Use FRONTEND_URL or FRONTEND_ORIGINS (comma separated) from env so you don't have to change code each deploy
const frontendOrigins = (process.env.FRONTEND_ORIGINS || process.env.FRONTEND_URL || 'http://localhost:5173')
  .split(',')
  .map(s => s.trim())
const allowedOrigins = [
  // keep the local dev entry and any build-time example domains if you want
  ...frontendOrigins,
  'https://major-project-frontend-y7th.vercel.app'
]

app.use(
  cors({
    origin: (origin, callback) => {
      // allow non-browser or same-origin requests (Postman, server-to-server)
      if (!origin) return callback(null, true)
      if (allowedOrigins.includes(origin)) return callback(null, true)
      // optional: log rejected origin for easier debugging
      console.warn('Blocked CORS origin:', origin)
      return callback(new Error('Not allowed by CORS'))
    },
    credentials: true,
    // optional: set optionsSuccessStatus if older browsers/clients need 200 for preflight
    optionsSuccessStatus: 200
  })
)

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
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // secure cookie in prod
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // none required for cross-site cookies
      // domain can be set if you need cookies shared across subdomains:
      // domain: process.env.SESSION_COOKIE_DOMAIN || undefined,
      maxAge: 1000 * 60 * 60 * 8 // 8 hours
    }
  })
)

// Static files
// Static files for uploads will be registered after multer setup so we can reuse the same uploadsDir

// Lightweight health check for Postman
app.get('/api/health', (req, res) => {
  res.status(200).json({ ok: true })
})

// Database connection
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/Clarity_Call'
if (process.env.NODE_ENV === 'production' && !process.env.MONGODB_URI) {
  console.error('MONGODB_URI must be set in production')
}

mongoose.set('strictQuery', true)
mongoose
  .connect(mongoUri)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err)
    process.exit(1)
  })

// Register mentor routes
import mentorRouter from './routes/mentor.js';
app.use('/api/mentors', mentorRouter);

// User Schema


const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true, lowercase: true, unique: true },
  password: { type: String, required: true },
  profileImage: { type: String, default: '' },
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

// File upload configuration
const uploadsDir = process.env.UPLOADS_DIR || (process.env.NODE_ENV === 'production' ? '/tmp/uploads' : path.resolve('uploads'))
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

// Serve uploaded files (ensure CORP allows cross-origin usage from frontend dev server)
app.use('/uploads', (req, res, next) => {
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin')
  next()
}, express.static(uploadsDir))

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
    const { firstName, lastName, email, password, bio, title, field, expertise } = req.body
    
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' })
    }

    const existing = await User.findOne({ email })
    if (existing) {
      return res.status(409).json({ message: 'Email already registered' })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    
    // Handle profile image
    let profileImagePath = '';
    if (req.file) {
      // If Cloudinary is configured, upload there in production
      if (process.env.NODE_ENV === 'production' && cloudinary.config().cloud_name) {
        try {
          const uploadResult = await cloudinary.uploader.upload(req.file.path, { folder: 'profile_images' })
          profileImagePath = uploadResult.secure_url
        } catch (e) {
          console.error('Cloudinary upload failed, falling back to local path', e)
          profileImagePath = `/uploads/${req.file.filename}`
        }
      } else {
        profileImagePath = `/uploads/${req.file.filename}`
      }
    }

    const user = await User.create({
      firstName,
      lastName, 
      email,
      password: hashedPassword,
      bio,
      title,
      field,
      expertise: expertise ? expertise.split(',').map(item => item.trim()) : [],
      profileImage: profileImagePath
    })

    return res.status(201).json(user)
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

app.get('/', (req, res) => {
  res.send('Welcome to the Backend API!')
})

// API Routes
app.use('/pages', pagesRouter)
app.post('/api/users/:id/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const { id } = req.params
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' })
    }

    let relativePath = `/uploads/${req.file.filename}`
    if (process.env.NODE_ENV === 'production' && cloudinary.config().cloud_name) {
      try {
        const uploadResult = await cloudinary.uploader.upload(req.file.path, { folder: 'avatars' })
        relativePath = uploadResult.secure_url
      } catch (e) {
        console.error('Cloudinary upload failed, using local path', e)
      }
    }
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
app.get('/admin/mentor-applications', requireAuth, isAdmin, async (req, res) => {
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
});

// Admin - Get application counts by status
app.get('/admin/mentor-applications/counts', requireAuth, isAdmin, async (req, res) => {
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
});

// Admin - Update mentor application status
app.put('/admin/mentor-applications/:id/status', requireAuth, isAdmin, async (req, res) => {
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
});

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
app.get('/admin/users', requireAuth, isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, 'firstName lastName email role title bio expertise createdAt isBlocked')
      .sort({ createdAt: -1 });
    res.status(200).json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin - Update user status (block/unblock)
app.put('/admin/users/:id/status', requireAuth, isAdmin, async (req, res) => {
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
});

// Admin - Delete user
app.delete('/admin/users/:id', requireAuth, isAdmin, async (req, res) => {
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

// Start server
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
