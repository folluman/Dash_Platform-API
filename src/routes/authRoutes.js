const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

// ROTA DE REGISTRO
router.post('/register', userController.user_create_post);

// ROTA DE LOGIN
router.post('/login', userController.user_login_post);

module.exports = router;
