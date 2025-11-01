import mongoose from 'mongoose';

const chatConversationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  mentorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  lastMessageAt: { type: Date, default: Date.now },
  lastMessageText: { type: String, default: '' },
  participants: { type: [mongoose.Schema.Types.ObjectId], ref: 'User', default: [] },
}, { timestamps: true, versionKey: false });

chatConversationSchema.index({ userId: 1, mentorId: 1 }, { unique: true });

const ChatConversation = mongoose.model('ChatConversation', chatConversationSchema);
export default ChatConversation;
