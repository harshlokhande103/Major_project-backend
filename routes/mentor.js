import express from 'express';
import MentorApplication from '../models/MentorApplication.js';

const router = express.Router();

// GET /api/mentors - Get all approved mentors
router.get('/', async (req, res) => {
  try {
    const mentors = await MentorApplication.find({ status: 'approved' });
    res.status(200).json(mentors);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch mentors' });
  }
});

export default router;
