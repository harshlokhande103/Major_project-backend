import mongoose from 'mongoose';

const mentorApplicationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true // एक यूजर केवल एक मेंटर एप्लीकेशन सबमिट कर सकता है
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  applicationDate: {
    type: Date,
    default: Date.now
  },
  // यहाँ मेंटर के बारे में अन्य विवरण जोड़े जा सकते हैं, जैसे अनुभव, कौशल, आदि।
  // उदाहरण के लिए:
  // experience: { type: String },
  // skills: [{ type: String }],
  // bio: { type: String },
});

const MentorApplication = mongoose.model('MentorApplication', mentorApplicationSchema);

export default MentorApplication;