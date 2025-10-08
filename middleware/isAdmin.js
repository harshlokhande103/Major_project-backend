const isAdmin = (req, res, next) => {
  const role = req?.session?.user?.role;
  if (role === 'admin') {
    return next();
  }
  return res.status(403).json({ message: 'Access denied. Admin privileges required.' });
};

export default isAdmin;