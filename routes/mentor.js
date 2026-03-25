import express from 'express';
import MentorApplication from '../models/MentorApplication.js';
import Slot from '../models/Slot.js';
import Booking from '../models/Booking.js';
import mongoose from 'mongoose';

const router = express.Router();

const requireAuth = (req, res, next) => {
  if (req.session?.user) return next();
  return res.status(401).json({ message: 'Unauthorized' });
};

const getUserModel = () => mongoose.models.User || mongoose.model('User');

const buildMentorResponse = async (filter = {}) => {
  const mentors = await MentorApplication.find({ status: 'approved', ...filter })
    .populate('userId', 'firstName lastName email profileImage bio title field expertise')
    .lean();

  const mentorUserIds = mentors
    .map(m => m?.userId?._id)
    .filter(Boolean)
    .map(id => new mongoose.Types.ObjectId(String(id)));

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
    ratingRows.map(r => [
      String(r._id),
      { rating: Number((r.avgRating || 0).toFixed(1)), reviews: Number(r.reviews || 0) }
    ])
  );

  return mentors
    .filter(mentor => mentor?.userId?._id)
    .map(mentor => ({
      _id: mentor._id,
      name: mentor.name || `${mentor.userId.firstName} ${mentor.userId.lastName}`.trim(),
      firstName: mentor.userId.firstName,
      lastName: mentor.userId.lastName,
      email: mentor.userId.email,
      profileImage: mentor.userId.profileImage,
      bio: mentor.bio || mentor.userId.bio,
      field: mentor.userId.field || mentor.domain || '',
      expertise: mentor.userId.expertise || [],
      phoneNumber: mentor.phoneNumber,
      linkedin: mentor.linkedin,
      portfolio: mentor.portfolio,
      status: mentor.status,
      applicationDate: mentor.applicationDate,
      rating: ratingMap.get(String(mentor.userId._id))?.rating || 0,
      reviews: ratingMap.get(String(mentor.userId._id))?.reviews || 0
    }));
};

const handleGetAllMentors = async (req, res) => {
  try {
    const mentorsWithUserData = await buildMentorResponse();
    res.status(200).json(mentorsWithUserData);
  } catch (err) {
    console.error('Error fetching mentors:', err);
    res.status(500).json({ error: 'Failed to fetch mentors' });
  }
};

// GET /api/mentors - Backward-compatible alias for all approved mentors
router.get('/', handleGetAllMentors);

// GET /api/mentors/all - Get all approved mentors with user data
router.get('/all', handleGetAllMentors);

// GET /api/mentors/recommended - Get approved mentors matching logged-in mentee field
router.get('/recommended', requireAuth, async (req, res) => {
  try {
    const userId = req.session?.user?.id;
    const User = getUserModel();
    const user = await User.findById(userId).select('field email').lean();

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userField = String(user.field || '').trim();
    if (!userField) {
      return res.status(200).json([]);
    }

    const mentorsWithUserData = await buildMentorResponse();
    const normalizedUserId = String(userId || '');
    const normalizedUserEmail = String(user.email || '').toLowerCase();

    const filteredMentors = mentorsWithUserData.filter(mentor => {
      const mentorId = String(mentor._id || '');
      const mentorEmail = String(mentor.email || '').toLowerCase();
      if (normalizedUserId && mentorId === normalizedUserId) return false;
      if (normalizedUserEmail && mentorEmail === normalizedUserEmail) return false;
      return String(mentor.field || '').trim().toLowerCase() === userField.toLowerCase();
    });

    res.status(200).json(filteredMentors);
  } catch (err) {
    console.error('Error fetching recommended mentors:', err);
    res.status(500).json({ error: 'Failed to fetch recommended mentors' });
  }
});

// GET /api/mentors/:id/slots - Get slots for a specific mentor
router.get('/:id/slots', async (req, res) => {
  try {
    const { id } = req.params;

    // Validate mentor exists and is approved
    const mentor = await MentorApplication.findOne({ _id: id, status: 'approved' });
    if (!mentor) {
      return res.status(404).json({ error: 'Mentor not found or not approved' });
    }

    // Fetch all slots for this mentor first
    const slots = await Slot.find({ mentorId: mentor.userId }).sort({ start: 1 });
    if (!slots.length) return res.status(200).json([]);

    // Hide slots that are already booked (except cancelled bookings, which can be rebooked)
    const slotIds = slots.map((s) => s._id);
    const booked = await Booking.find({
      slotId: { $in: slotIds },
      status: { $ne: 'cancelled' }
    }).select('slotId').lean();

    const bookedSlotSet = new Set(booked.map((b) => String(b.slotId)));
    const availableSlots = slots.filter((s) => !bookedSlotSet.has(String(s._id)));

    res.status(200).json(availableSlots);
  } catch (err) {
    console.error('Error fetching mentor slots:', err);
    res.status(500).json({ error: 'Failed to fetch mentor slots' });
  }
});

export default router;
