import mongoose from 'mongoose';

const chatMessageSchema = new mongoose.Schema({
  conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'ChatConversation', required: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, trim: true, default: '' },
  attachments: [{
    url: { type: String, required: true },
    name: { type: String, default: '' },
    size: { type: Number, default: 0 },
    mime: { type: String, default: '' },
    data: { type: Buffer }
  }],
  readBy: { type: [mongoose.Schema.Types.ObjectId], ref: 'User', default: [] },
}, { timestamps: true, versionKey: false });

chatMessageSchema.index({ conversationId: 1, createdAt: 1 });

const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema);
export default ChatMessage;
