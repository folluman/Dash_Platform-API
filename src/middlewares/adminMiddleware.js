const User = require('../models/User');

exports.isAdmin = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id).exec();
        
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied. Admins only.' });
        }
        next();
    }
    catch (error) {
        console.error('Error in admin middleware:', error);
        return res.status(500).json({ error: 'Internal server error.' });
    }
}
