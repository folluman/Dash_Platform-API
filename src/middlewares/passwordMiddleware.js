const User = require('../models/User');

// BLOQUEIA O USO DA API ENQUANTO O USUÁRIO NÃO TROCAR A SENHA DO PRIMEIRO ACESSO.
// USAR SEMPRE DEPOIS DO verifyToken (PRECISA DO req.user).
exports.requirePasswordChanged = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id).exec();

        if (!user) {
            return res.status(401).json({ error: 'User not found.' });
        }

        if (user.mustChangePassword) {
            return res.status(403).json({
                error: 'Você precisa trocar sua senha antes de continuar.',
                code: 'PASSWORD_CHANGE_REQUIRED'
            });
        }

        next();
    }
    catch (error) {
        console.error('Error in password middleware:', error);
        return res.status(500).json({ error: 'Internal server error.' });
    }
}
