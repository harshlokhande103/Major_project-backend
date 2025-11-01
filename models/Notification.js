import mongoose from 'mongoose';

const notificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: true
  },
  message: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['mentor_approved', 'mentor_rejected', 'general', 'chat_message'],
    default: 'general'
  },
  data: { type: Object, default: {} },
  isRead: {
    type: Boolean,
    default: false
  },
  readAt: {
    type: Date
  }
}, { timestamps: true });

const Notification = mongoose.model('Notification', notificationSchema);

export default Notification;
