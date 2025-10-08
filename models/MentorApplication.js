import mongoose from 'mongoose';

const mentorApplicationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  name: { type: String, trim: true, default: '' },
  phoneNumber: { type: String, trim: true, default: '' },
  bio: { type: String, trim: true, default: '' },
  domain: { type: String, trim: true, default: '' },
  linkedin: { type: String, trim: true, default: '' },
  portfolio: { type: String, trim: true, default: '' },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  applicationDate: {
    type: Date,
    default: Date.now
  }
});

const MentorApplication = mongoose.model('MentorApplication', mentorApplicationSchema);

export default MentorApplication;