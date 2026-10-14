const User = require('../models/User');
const Dash = require('../models/Dash');
require('dotenv').config();
const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { passwordValidator, generateTemporaryPassword } = require('../services/passwordService');
const isProduction = process.env.NODE_ENV === 'production';
const authCookieOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    path: '/',
};

exports.user_list = asyncHandler(async (req, res, next) => {
    const users = await User.find().exec();
    res.json(users);
});

exports.user_create_post = [
    body('username')
        .trim()
        .isLength({ min: 1 })
        .withMessage('Username must be specified.')
        .escape()
        .matches(/^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*$/)
        .withMessage('O usuário deve conter apenas letras, números e pontos (o ponto não pode ficar no início, no fim ou repetido).'),
    body('name')
        .isString()
        .trim()
        .isLength({ min: 1, max: 100 })
        .withMessage('Informe o nome (até 100 caracteres).'),
    passwordValidator('password'),
    body('email')
        .trim()
        .isEmail()
        .withMessage('Please enter a valid email.')
        .normalizeEmail(),

    asyncHandler(async (req, res, next) => {
        const username = await User.findOne({ username: req.body.username }).exec();

        if (username) {
            return res.status(400).json({ error: 'Username already exists!' });
        }

        const errors = validationResult(req);

        const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

        // DESCOBRE SE QUEM ESTÁ CRIANDO É UM ADMIN LOGADO
        let createdByAdmin = false;
        if (req.cookies?.token) {
            try {
                const decoded = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
                const requester = await User.findById(decoded.id).exec();
                createdByAdmin = Boolean(requester && requester.role === 'admin');
            } catch (error) {
                // TOKEN INVÁLIDO: TRATA COMO CADASTRO PÚBLICO
            }
        }

        // SÓ UM ADMIN PODE CRIAR OUTRO ADMIN
        const role = req.body.role === 'admin' && createdByAdmin ? 'admin' : 'user';

        const user = new User({
            username: req.body.username,
            name: req.body.name,
            password: hashedPassword,
            email: req.body.email,
            role,
            // A SENHA FOI DEFINIDA PELO ADMIN, ENTÃO O USUÁRIO TROCA NO PRIMEIRO LOGIN
            mustChangePassword: createdByAdmin,
        })

        if(!errors.isEmpty()) {
            return res.status(400).json({
                // A PRIMEIRA MENSAGEM VAI EM error PARA O FRONT CONSEGUIR MOSTRAR O MOTIVO
                error: errors.array()[0].msg,
                details: errors.array()
             });
        }

        await user.save();
        res.status(201).json({ message: 'User created successfully!' });
    }
    )
]

// ADMIN EDITA UM USUÁRIO
exports.user_update = [
    body('username')
        .isString()
        .trim()
        .matches(/^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*$/)
        .withMessage('O usuário deve conter apenas letras, números e pontos (o ponto não pode ficar no início, no fim ou repetido).'),
    body('name')
        .isString()
        .trim()
        .isLength({ min: 1, max: 100 })
        .withMessage('Informe o nome (até 100 caracteres).'),
    body('email')
        .trim()
        .isEmail()
        .withMessage('Informe um email válido.')
        .normalizeEmail(),
    body('role')
        .isIn(['user', 'admin'])
        .withMessage('Perfil inválido.'),
    passwordValidator('password', { optional: true }),

    asyncHandler(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg, details: errors.array() });
        }

        const { id } = req.params;
        if (!mongoose.isValidObjectId(id)) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }

        const user = await User.findById(id).exec();
        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }

        // EVITA QUE O ADMIN TIRE O PRÓPRIO ACESSO DE ADMINISTRADOR
        if (id === req.user.id && req.body.role !== 'admin') {
            return res.status(400).json({ error: 'Você não pode remover o seu próprio acesso de administrador.' });
        }

        const { username, name, email, role, password } = req.body;

        const usernameTaken = await User.exists({ username, _id: { $ne: id } });
        if (usernameTaken) {
            return res.status(400).json({ error: 'Este usuário (login) já está em uso.' });
        }

        const emailTaken = await User.exists({ email, _id: { $ne: id } });
        if (emailTaken) {
            return res.status(400).json({ error: 'Este email já está em uso.' });
        }

        user.username = username;
        user.name = name;
        user.email = email;
        user.role = role;

        // SENHA DEFINIDA PELO ADMIN: O USUÁRIO TROCA NO PRÓXIMO LOGIN (MESMA REGRA DO CADASTRO)
        if (password) {
            user.password = await bcrypt.hash(password, saltRounds);
            if (id !== req.user.id) user.mustChangePassword = true;
        }

        await user.save();

        res.status(200).json({ message: 'Usuário atualizado com sucesso!' });
    })
]

// LOGIN USER
exports.user_login_post = asyncHandler(async (req, res, next) => {
    try {
        const {username, password} = req.body;

        const user = await User.findOne({ username }).select('+password').exec();

        if (!user) {
            return res.status(400).json({ error: 'Invalid username or password.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid password.' });
        }

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.cookie('token', token, {
            ...authCookieOptions,
            maxAge: 3600000 // 1 HORA
        });

        return res.status(200).json({
            message: 'Login successful!',
            user: {
                id: user._id,
                username: user.username,
                name: user.name || user.username,
                role: user.role,
                mustChangePassword: Boolean(user.mustChangePassword),
            },
        })
    }
    catch (error) {
        res.status(500).json({ error: 'Internal server error.' });
    }
})

// DADOS DO USUÁRIO LOGADO (LIDOS DO BANCO, PARA REFLETIR MUDANÇAS SEM PRECISAR DE NOVO LOGIN)
exports.user_me = asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.user.id).exec();

    if (!user) {
        return res.status(401).json({ error: 'User not found.' });
    }

    res.json({
        user: user.username,
        name: user.name || user.username,
        role: user.role,
        mustChangePassword: Boolean(user.mustChangePassword),
    });
})

// TROCA DE SENHA DO PRÓPRIO USUÁRIO
exports.user_change_password = [
    body('currentPassword')
        .isString()
        .isLength({ min: 1 })
        .withMessage('Informe a senha atual.'),
    passwordValidator('newPassword'),

    asyncHandler(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }

        const user = await User.findById(req.user.id).select('+password').exec();
        if (!user) {
            return res.status(401).json({ error: 'User not found.' });
        }

        const isCurrentValid = await bcrypt.compare(req.body.currentPassword, user.password);
        if (!isCurrentValid) {
            return res.status(400).json({ error: 'A senha atual está incorreta.' });
        }

        // MESMO TRIM DO CADASTRO, PARA O LOGIN COMPARAR O MESMO VALOR
        const newPassword = req.body.newPassword.trim();

        const isSamePassword = await bcrypt.compare(newPassword, user.password);
        if (isSamePassword) {
            return res.status(400).json({ error: 'A nova senha deve ser diferente da atual.' });
        }

        user.password = await bcrypt.hash(newPassword, saltRounds);
        user.mustChangePassword = false;
        await user.save();

        res.status(200).json({ message: 'Senha alterada com sucesso!' });
    })
]

// LOGOUT USER
exports.user_logout_post = asyncHandler(async (req, res, next) => {
    // PRECISA DAS MESMAS OPÇÕES DO LOGIN, SENÃO O NAVEGADOR NÃO APAGA O COOKIE
    res.clearCookie('token', authCookieOptions)
    res.status(200).json({ message: 'Logout successful!' });
})

// ADMIN RESETA A SENHA DE UM USUÁRIO: GERA UMA SENHA TEMPORÁRIA E OBRIGA A TROCA NO PRÓXIMO LOGIN
exports.user_reset_password = asyncHandler(async (req, res, next) => {
    const {id} = req.params;

    if (!mongoose.isValidObjectId(id)) {
        return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    // PARA A PRÓPRIA CONTA, O ADMIN USA A TROCA DE SENHA NORMAL
    if (id === req.user.id) {
        return res.status(400).json({ error: 'Para alterar a sua própria senha, use a opção de trocar senha.' });
    }

    const user = await User.findById(id).exec();
    if (!user) {
        return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    const temporaryPassword = generateTemporaryPassword();

    user.password = await bcrypt.hash(temporaryPassword, saltRounds);
    user.mustChangePassword = true;
    await user.save();

    // A SENHA SÓ É DEVOLVIDA AQUI, UMA ÚNICA VEZ (NO BANCO FICA APENAS O HASH)
    res.status(200).json({
        message: 'Senha resetada com sucesso!',
        username: user.username,
        temporaryPassword,
    });
})

exports.user_delete = asyncHandler(async (req, res, next) => {
    const {id} = req.params;

    // IMPEDE O ADMIN DE EXCLUIR A PRÓPRIA CONTA
    if (id === req.user.id) {
        return res.status(400).json({ error: 'You cannot delete your own account.' });
    }

    const deletedUser = await User.findByIdAndDelete(id).exec();

    if (!deletedUser) {
        return res.status(404).json({ error: 'User not found.' });
    }

    // REMOVE O USUÁRIO EXCLUÍDO DAS LISTAS DE ACESSO DOS DASHBOARDS
    await Dash.updateMany({ allowedUsers: id }, { $pull: { allowedUsers: id } }).exec();

    res.status(200).json({ message: 'User deleted successfully!' });
})