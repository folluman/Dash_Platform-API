const jwt = require('jsonwebtoken');

exports.verifyToken = (req, res, next) => {
    // PEGANDO O TOKEN E ARMAZENANDO NO COOKIES
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        return next();
    }
    
    catch (error) {
        return res.status(401).json({ error: 'Invalid or expired session. Try logging in again.' });
    }
}
