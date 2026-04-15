import express from 'express';
import mongoose from 'mongoose';
import MentorApplication from '../models/MentorApplication.js';
import Booking from '../models/Booking.js';
import Notification from '../models/Notification.js';
import ChatConversation from '../models/ChatConversation.js';

const router = express.Router();

const requireAuth = (req, res, next) => {
  if (req.session?.user?.id) return next();
  return res.status(401).json({ message: 'Unauthorized' });
};

const getUserModel = () => mongoose.models.User || mongoose.model('User');

const getNormalizedBookingStatus = (booking) => {
  const raw = String(booking?.status || '').trim().toLowerCase();
  if (raw === 'confirmed' || raw === 'completed' || raw === 'cancelled') return raw;
  return 'pending';
};

const getBookingStartDate = (booking) => {
  const rawStart = booking?.slotId?.start;
  if (!rawStart) return null;
  const parsed = new Date(rawStart);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const mapMentorCard = (mentor, ratingMap) => ({
  id: String(mentor._id),
  name: mentor.name || `${mentor.userId?.firstName || ''} ${mentor.userId?.lastName || ''}`.trim(),
  firstName: mentor.userId?.firstName || '',
  lastName: mentor.userId?.lastName || '',
  email: mentor.userId?.email || '',
  profileImage: mentor.userId?.profileImage || '',
  bio: mentor.bio || mentor.userId?.bio || '',
  field: mentor.userId?.field || mentor.domain || '',
  expertise: mentor.userId?.expertise || [],
  phoneNumber: mentor.phoneNumber || '',
  linkedin: mentor.linkedin || '',
  portfolio: mentor.portfolio || '',
  rating: ratingMap.get(String(mentor.userId?._id))?.rating || 0,
  reviews: ratingMap.get(String(mentor.userId?._id))?.reviews || 0,
  status: mentor.status,
  applicationDate: mentor.applicationDate
});

const buildMentorCards = async () => {
  const mentors = await MentorApplication.find({ status: 'approved' })
    .populate('userId', 'firstName lastName email profileImage bio field expertise')
    .lean();

  const mentorUserIds = mentors
    .map((mentor) => mentor?.userId?._id)
    .filter(Boolean)
    .map((id) => new mongoose.Types.ObjectId(String(id)));

  const ratingRows = mentorUserIds.length
    ? await Booking.aggregate([
        {
          $match: {
            mentorId: { $in: mentorUserIds },
            status: 'completed',
            ratingValue: { $gte: 1, $lte: 5 }
          }
        },
        {
          $group: {
            _id: '$mentorId',
            avgRating: { $avg: '$ratingValue' },
            reviews: { $sum: 1 }
          }
        }
      ])
    : [];

  const ratingMap = new Map(
    ratingRows.map((row) => [
      String(row._id),
      {
        rating: Number((row.avgRating || 0).toFixed(1)),
        reviews: Number(row.reviews || 0)
      }
    ])
  );

  return mentors
    .filter((mentor) => mentor?.userId?._id)
    .map((mentor) => mapMentorCard(mentor, ratingMap));
};

const buildChatCards = async (userId) => {
  const me = new mongoose.Types.ObjectId(String(userId));
  const conversations = await ChatConversation.find({ participants: me })
    .populate('userId', 'firstName lastName email profileImage')
    .populate('mentorId', 'firstName lastName email profileImage')
    .sort({ updatedAt: -1 })
    .lean();

  return conversations
    .filter((conversation) => String(conversation.userId?._id || conversation.userId) === String(userId))
    .map((conversation) => {
      const counterpart = conversation.mentorId;
      const counterpartName = `${counterpart?.firstName || ''} ${counterpart?.lastName || ''}`.trim() || counterpart?.email || 'Mentor';
      return {
        id: String(conversation._id),
        conversationId: String(conversation._id),
        userId: String(conversation.userId?._id || conversation.userId || ''),
        mentorId: String(conversation.mentorId?._id || conversation.mentorId || ''),
        counterpart: {
          id: String(counterpart?._id || ''),
          firstName: counterpart?.firstName || '',
          lastName: counterpart?.lastName || '',
          email: counterpart?.email || '',
          profileImage: counterpart?.profileImage || ''
        },
        counterpartName,
        lastMessageAt: conversation.lastMessageAt,
        lastMessageText: conversation.lastMessageText || '',
        updatedAt: conversation.updatedAt
      };
    });
};

const buildBookingPayload = async (userId) => {
  const bookings = await Booking.find({ userId })
    .populate('mentorId', 'firstName lastName email profileImage title')
    .populate('slotId')
    .sort({ createdAt: -1 })
    .lean();

  const safeBookings = bookings.filter((booking) => booking?.slotId?.start);
  const now = Date.now();
  const grouped = { upcoming: [], past: [], cancelled: [] };

  safeBookings.forEach((booking) => {
    const status = getNormalizedBookingStatus(booking);
    if (status === 'cancelled') {
      grouped.cancelled.push(booking);
      return;
    }
    if (status === 'completed') {
      grouped.past.push(booking);
      return;
    }

    const startDate = getBookingStartDate(booking);
    if (startDate && startDate.getTime() < now) {
      grouped.past.push(booking);
    } else {
      grouped.upcoming.push(booking);
    }
  });

  return {
    summary: {
      total: safeBookings.length,
      upcoming: grouped.upcoming.length,
      past: grouped.past.length,
      cancelled: grouped.cancelled.length
    },
    bookings: safeBookings,
    grouped
  };
};

router.get('/home', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const User = getUserModel();
    const user = await User.findById(userId).select('firstName lastName email profileImage bio field expertise').lean();
    if (!user) return res.status(404).json({ message: 'User not found' });

    const mentors = await buildMentorCards();
    const field = String(user.field || '').trim().toLowerCase();
    const recommendedMentors = field
      ? mentors.filter((mentor) => String(mentor.field || '').trim().toLowerCase() === field).slice(0, 6)
      : [];

    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();

    res.status(200).json({
      user,
      recommendedMentors,
      notifications,
      unreadNotificationCount: notifications.filter((item) => !item.isRead).length
    });
  } catch (err) {
    console.error('Error loading seeker home dashboard:', err);
    res.status(500).json({ message: 'Failed to load home dashboard' });
  }
});

router.get('/bookings', requireAuth, async (req, res) => {
  try {
    const payload = await buildBookingPayload(req.session.user.id);
    res.status(200).json(payload);
  } catch (err) {
    console.error('Error loading seeker bookings dashboard:', err);
    res.status(500).json({ message: 'Failed to load bookings dashboard' });
  }
});

router.get('/chat', requireAuth, async (req, res) => {
  try {
    const conversations = await buildChatCards(req.session.user.id);
    res.status(200).json({
      summary: {
        total: conversations.length
      },
      conversations
    });
  } catch (err) {
    console.error('Error loading seeker chat dashboard:', err);
    res.status(500).json({ message: 'Failed to load chat dashboard' });
  }
});

router.get('/find-people', requireAuth, async (req, res) => {
  try {
    const query = String(req.query.q || '').trim().toLowerCase();
    const field = String(req.query.field || '').trim().toLowerCase();
    const currentUserId = String(req.session.user.id || '');
    const User = getUserModel();
    const currentUser = await User.findById(currentUserId).select('email').lean();
    const currentUserEmail = String(currentUser?.email || '').toLowerCase();

    const mentors = (await buildMentorCards()).filter((mentor) => {
      if (String(mentor.id) === currentUserId) return false;
      if (currentUserEmail && String(mentor.email || '').toLowerCase() === currentUserEmail) return false;

      const matchesQuery = !query || [
        mentor.name,
        mentor.email,
        mentor.field
      ].some((value) => String(value || '').toLowerCase().includes(query));

      const matchesField = !field || String(mentor.field || '').toLowerCase() === field;
      return matchesQuery && matchesField;
    });

    res.status(200).json({
      summary: {
        total: mentors.length
      },
      mentors
    });
  } catch (err) {
    console.error('Error loading seeker find-people dashboard:', err);
    res.status(500).json({ message: 'Failed to load find people dashboard' });
  }
});

router.get('/profile', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const User = getUserModel();
    const user = await User.findById(userId).select('-password').lean();
    if (!user) return res.status(404).json({ message: 'User not found' });

    const bookingPayload = await buildBookingPayload(userId);
    const completedBookings = bookingPayload.bookings.filter((booking) => getNormalizedBookingStatus(booking) === 'completed');
    const ratingRows = completedBookings.filter((booking) => Number(booking.ratingValue) >= 1);
    const averageRating = ratingRows.length
      ? Number((ratingRows.reduce((sum, booking) => sum + Number(booking.ratingValue || 0), 0) / ratingRows.length).toFixed(1))
      : 0;

    const recentActivity = [
      ...bookingPayload.bookings.slice(0, 3).map((booking) => ({
        type: 'booking_created',
        title: `Booked session with ${(booking.mentorId?.firstName || '')} ${(booking.mentorId?.lastName || '')}`.trim(),
        createdAt: booking.createdAt
      })),
      ...completedBookings.slice(0, 3).map((booking) => ({
        type: 'booking_completed',
        title: `Completed session with ${(booking.mentorId?.firstName || '')} ${(booking.mentorId?.lastName || '')}`.trim(),
        createdAt: booking.updatedAt
      }))
    ]
      .filter((item) => item.title)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, 6);

    res.status(200).json({
      profile: user,
      stats: {
        sessionsBooked: bookingPayload.summary.total,
        completedSessions: completedBookings.length,
        averageRating
      },
      recentActivity
    });
  } catch (err) {
    console.error('Error loading seeker profile dashboard:', err);
    res.status(500).json({ message: 'Failed to load profile dashboard' });
  }
});

router.get('/rewards', requireAuth, async (req, res) => {
  try {
    const bookingPayload = await buildBookingPayload(req.session.user.id);
    const completedSessions = bookingPayload.summary.past;
    const totalPoints = completedSessions * 10;

    res.status(200).json({
      totalPoints,
      rewards: [
        {
          id: 'sessions-completed',
          title: 'Sessions Completed',
          description: 'Earn 10 points for every completed mentoring session.',
          value: completedSessions
        }
      ]
    });
  } catch (err) {
    console.error('Error loading seeker rewards dashboard:', err);
    res.status(500).json({ message: 'Failed to load rewards dashboard' });
  }
});

router.get('/categories', requireAuth, async (req, res) => {
  try {
    const mentors = await buildMentorCards();
    const categoryMap = new Map();

    mentors.forEach((mentor) => {
      const key = String(mentor.field || 'Other').trim() || 'Other';
      categoryMap.set(key, (categoryMap.get(key) || 0) + 1);
    });

    const categories = Array.from(categoryMap.entries()).map(([name, mentorCount]) => ({
      name,
      mentorCount
    }));

    res.status(200).json({ categories });
  } catch (err) {
    console.error('Error loading seeker categories dashboard:', err);
    res.status(500).json({ message: 'Failed to load categories dashboard' });
  }
});

router.get('/news', requireAuth, async (req, res) => {
  try {
    const items = await Notification.find({ userId: req.session.user.id })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    res.status(200).json({
      items: items.map((item) => ({
        id: String(item._id),
        title: item.title,
        message: item.message,
        type: item.type,
        isRead: item.isRead,
        createdAt: item.createdAt
      }))
    });
  } catch (err) {
    console.error('Error loading seeker news dashboard:', err);
    res.status(500).json({ message: 'Failed to load news dashboard' });
  }
});

export default router;
