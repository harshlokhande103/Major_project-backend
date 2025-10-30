import mongoose from 'mongoose';

const slotSchema = new mongoose.Schema({
  mentorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  start: { type: Date, required: true },
  end: { type: Date }, // optional if duration provided
  durationMinutes: { type: Number }, // optional
  price: { type: Number, default: 0 },
  label: { type: String, default: '' },
  meta: { type: Object, default: {} }
}, { timestamps: true });

const Slot = mongoose.model('Slot', slotSchema);

export default Slot;
