import express from 'express';
import mongoose from 'mongoose';
import ChatConversation from '../models/ChatConversation.js';
import ChatMessage from '../models/ChatMessage.js';
import Notification from '../models/Notification.js';
import multer from 'multer';

const router = express.Router();

// simple auth gate using session
const requireAuth = (req, res, next) => {
  if (req.session?.user?.id) return next();
  return res.status(401).json({ message: 'Unauthorized' });
};

// Configure memory storage for chat attachments; data will be stored in MongoDB
const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } }); // 20MB limit

// Create or get a conversation between a user and mentor
router.post('/conversation', requireAuth, async (req, res) => {
  try {
    const { userId, mentorId } = req.body;
    if (!userId || !mentorId) return res.status(400).json({ message: 'userId and mentorId required' });

    const a = new mongoose.Types.ObjectId(String(userId));
    const b = new mongoose.Types.ObjectId(String(mentorId));

    let conv = await ChatConversation.findOne({ userId: a, mentorId: b });
    if (!conv) {
      conv = await ChatConversation.create({ userId: a, mentorId: b, participants: [a, b] });
    }
    return res.status(200).json({ id: conv._id });
  } catch (e) {
    console.error('Create/get conversation error', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Send a message with a single attachment (image/video/pdf/any file)
router.post('/messages/attachment', requireAuth, upload.single('file'), async (req, res) => {
  try {
    const { conversationId, text = '' } = req.body;
    if (!conversationId) return res.status(400).json({ message: 'conversationId required' });
    if (!req.file) return res.status(400).json({ message: 'file is required' });

    const me = new mongoose.Types.ObjectId(String(req.session.user.id));
    const conv = await ChatConversation.findById(conversationId);
    if (!conv) return res.status(404).json({ message: 'Conversation not found' });
    if (!conv.participants.map(String).includes(String(me))) return res.status(403).json({ message: 'Forbidden' });

    // First create message with placeholder; then update URL using created id
    const provisional = {
      url: '',
      name: req.file.originalname || 'file',
      size: req.file.size || 0,
      mime: req.file.mimetype || '',
      data: req.file.buffer
    };
    let msg = await ChatMessage.create({ conversationId, senderId: me, text: text || '', attachments: [provisional] });
    const rel = `/api/chat/attachments/${msg._id}/0`;
    msg.attachments[0].url = rel;
    await msg.save();

    conv.lastMessageAt = new Date();
    conv.lastMessageText = text ? text.slice(0, 500) : (msg.attachments[0].name || 'Attachment');
    await conv.save();

    const recipient = conv.participants.find(p => String(p) !== String(me));
    if (recipient) {
      await Notification.create({
        userId: recipient,
        title: 'New attachment',
        message: text ? text.slice(0, 80) : (msg.attachments[0].name || 'Attachment'),
        type: 'chat_message',
        data: { conversationId: conv._id.toString() }
      });
    }

    return res.status(201).json(msg);
  } catch (e) {
    console.error('Send attachment error', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Fetch a chat attachment by message id and index
router.get('/attachments/:messageId/:index', requireAuth, async (req, res) => {
  try {
    const { messageId, index } = req.params;
    const msg = await ChatMessage.findById(messageId).lean();
    if (!msg) return res.status(404).json({ message: 'Message not found' });

    // Authorization: must be participant of the conversation
    const conv = await ChatConversation.findById(msg.conversationId).lean();
    if (!conv) return res.status(404).json({ message: 'Conversation not found' });
    const me = String(req.session.user.id);
    if (!conv.participants.map(String).includes(me)) return res.status(403).json({ message: 'Forbidden' });

    const idx = Number(index) || 0;
    const att = msg.attachments?.[idx];
    if (!att || !att.data) return res.status(404).json({ message: 'Attachment not found' });
    res.setHeader('Content-Type', att.mime || 'application/octet-stream');
    res.status(200).send(att.data);
  } catch (e) {
    console.error('Fetch attachment error', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// List conversations for current user
router.get('/conversations', requireAuth, async (req, res) => {
  try {
    const me = new mongoose.Types.ObjectId(String(req.session.user.id));
    const list = await ChatConversation.find({ participants: me })
      .sort({ updatedAt: -1 })
      .lean();
    return res.status(200).json(list);
  } catch (e) {
    console.error('List conversations error', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Get conversation detail with participant info
router.get('/conversations/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const me = new mongoose.Types.ObjectId(String(req.session.user.id));
    let conv = await ChatConversation.findById(id)
      .populate('userId', 'firstName lastName email profileImage')
      .populate('mentorId', 'firstName lastName email profileImage')
      .lean();
    if (!conv) return res.status(404).json({ message: 'Conversation not found' });
    const isParticipant = [conv.userId?._id, conv.mentorId?._id].map(String).includes(String(me));
    if (!isParticipant) return res.status(403).json({ message: 'Forbidden' });

    const meIdStr = String(me);
    const userIdStr = String(conv.userId?._id || conv.userId);
    const mentorIdStr = String(conv.mentorId?._id || conv.mentorId);
    const counterpart = meIdStr === userIdStr ? conv.mentorId : conv.userId;
    const fullName = counterpart?.firstName || counterpart?.lastName
      ? `${counterpart?.firstName || ''} ${counterpart?.lastName || ''}`.trim()
      : (counterpart?.email || '');

    return res.status(200).json({
      id: conv._id,
      userId: conv.userId?._id || conv.userId,
      mentorId: conv.mentorId?._id || conv.mentorId,
      lastMessageAt: conv.lastMessageAt,
      lastMessageText: conv.lastMessageText,
      counterpart: {
        id: counterpart?._id || null,
        firstName: counterpart?.firstName || '',
        lastName: counterpart?.lastName || '',
        email: counterpart?.email || '',
        profileImage: counterpart?.profileImage || ''
      },
      counterpartName: fullName
    });
  } catch (e) {
    console.error('Conversation detail error', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// List messages in a conversation
router.get('/conversations/:id/messages', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const me = new mongoose.Types.ObjectId(String(req.session.user.id));
    const conv = await ChatConversation.findById(id);
    if (!conv) return res.status(404).json({ message: 'Conversation not found' });
    if (!conv.participants.map(String).includes(String(me))) return res.status(403).json({ message: 'Forbidden' });

    const messages = await ChatMessage.find({ conversationId: id }).sort({ createdAt: 1 }).lean();
    return res.status(200).json(messages);
  } catch (e) {
    console.error('List messages error', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Send a new message
router.post('/messages', requireAuth, async (req, res) => {
  try {
    const { conversationId, text } = req.body;
    if (!conversationId || !text) return res.status(400).json({ message: 'conversationId and text required' });

    const me = new mongoose.Types.ObjectId(String(req.session.user.id));
    const conv = await ChatConversation.findById(conversationId);
    if (!conv) return res.status(404).json({ message: 'Conversation not found' });
    if (!conv.participants.map(String).includes(String(me))) return res.status(403).json({ message: 'Forbidden' });

    const msg = await ChatMessage.create({ conversationId, senderId: me, text });

    conv.lastMessageAt = new Date();
    conv.lastMessageText = text.slice(0, 500);
    await conv.save();

    const recipient = conv.participants.find(p => String(p) !== String(me));
    if (recipient) {
      await Notification.create({
        userId: recipient,
        title: 'New message',
        message: text.length > 80 ? text.slice(0, 77) + '...' : text,
        type: 'chat_message',
        data: { conversationId: conv._id.toString() }
      });
    }

    return res.status(201).json(msg);
  } catch (e) {
    console.error('Send message error', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

export default router;
