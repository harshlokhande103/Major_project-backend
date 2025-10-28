import express from 'express';
import MentorApplication from '../models/MentorApplication.js';
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
      domain: mentor.domain,
      title: mentor.userId.title,
      field: mentor.userId.field,
      expertise: mentor.userId.expertise,
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

export default router;
