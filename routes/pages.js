import express from 'express'

const router = express.Router()

// Lightweight page endpoints to help Postman verification
// These do not alter app logic and are safe to call anytime

router.get('/home', (req, res) => {
  res.status(200).json({ ok: true, page: 'home' })
})

router.get('/login', (req, res) => {
  res.status(200).json({ ok: true, page: 'login' })
})

router.get('/register', (req, res) => {
  res.status(200).json({ ok: true, page: 'register' })
})

router.get('/dashboard', (req, res) => {
  res.status(200).json({ ok: true, page: 'dashboard' })
})

router.get('/seeker-dashboard', (req, res) => {
  res.status(200).json({ ok: true, page: 'seekerDashboard' })
})

router.get('/verify', (req, res) => {
  res.status(200).json({ ok: true, page: 'verifyMentor' })
})

router.get('/admin', (req, res) => {
  res.status(200).json({ ok: true, page: 'adminDashboard' })
})

router.get('/admin/mentor-applications', (req, res) => {
  res.status(200).json({ ok: true, page: 'adminMentorApplications' })
})

export default router


