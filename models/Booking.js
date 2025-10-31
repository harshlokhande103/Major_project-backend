import mongoose from 'mongoose';

const bookingSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  slotId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Slot',
    required: true
  },
  mentorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['confirmed', 'cancelled', 'completed'],
    default: 'confirmed'
  },
  notes: {
    type: String,
    default: ''
  },
  meetingLink: {
    type: String,
    default: ''
  }
}, { timestamps: true });

// Compound index to prevent double booking same slot
bookingSchema.index({ slotId: 1 }, { unique: true });

const Booking = mongoose.model('Booking', bookingSchema);

export default Booking;
