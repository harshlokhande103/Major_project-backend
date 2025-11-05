import express from 'express';
import MentorApplication from '../models/MentorApplication.js';
import Slot from '../models/Slot.js';
import mongoose from 'mongoose';

const router = express.Router();

// GET /api/mentors - Get all approved mentors with user data
router.get('/', async (req, res) => {
  try {
    const mentors = await MentorApplication.find({ status: 'approved' })
      .populate('userId', 'firstName lastName email profileImage bio title field expertise')
      .lean();
    
    // Transform the data to include user information
    const mentorsWithUserData = mentors.map(mentor => ({
      _id: mentor._id,
      name: mentor.name || `${mentor.userId.firstName} ${mentor.userId.lastName}`,
      firstName: mentor.userId.firstName,
      lastName: mentor.userId.lastName,
      email: mentor.userId.email,
      profileImage: mentor.userId.profileImage,
      bio: mentor.bio || mentor.userId.bio,
      // prefer user field; fallback to legacy domain if present
      field: mentor.userId.field || mentor.domain || '',
      phoneNumber: mentor.phoneNumber,
      linkedin: mentor.linkedin,
      portfolio: mentor.portfolio,
      status: mentor.status,
      applicationDate: mentor.applicationDate
    }));
    
    res.status(200).json(mentorsWithUserData);
  } catch (err) {
    console.error('Error fetching mentors:', err);
    res.status(500).json({ error: 'Failed to fetch mentors' });
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

    // Fetch slots for the mentor
    const slots = await Slot.find({ mentorId: mentor.userId }).sort({ start: 1 });

    res.status(200).json(slots);
  } catch (err) {
    console.error('Error fetching mentor slots:', err);
    res.status(500).json({ error: 'Failed to fetch mentor slots' });
  }
});

export default router;
