let express = require('express');
let router = express.Router();
const userController = require('../controllers/userController');
const { verify } = require('jsonwebtoken');
const { verifyToken } = require('../middlewares/authMiddleware')
const { isAdmin } = require('../middlewares/adminMiddleware')
const { requirePasswordChanged } = require('../middlewares/passwordMiddleware')

router.get('/list', verifyToken, requirePasswordChanged, isAdmin, userController.user_list);
router.post('/signup', userController.user_create_post);
router.delete('/delete/:id', verifyToken, requirePasswordChanged, isAdmin, userController.user_delete);
router.post('/reset-password/:id', verifyToken, requirePasswordChanged, isAdmin, userController.user_reset_password);
router.post('/login', userController.user_login_post);
router.post('/logout', userController.user_logout_post);
// ROTAS LIBERADAS MESMO ANTES DE TROCAR A SENHA DO PRIMEIRO ACESSO
router.get('/me', verifyToken, userController.user_me);
router.post('/change-password', verifyToken, userController.user_change_password);

module.exports = router;
