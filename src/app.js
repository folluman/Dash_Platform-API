require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');

const app = express();

app.set('trust proxy', 1);

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: 'Too many requests from this IP, please try again later.',
});

const createAccountLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 15,
    message: 'Too many accounts created from this IP, please try again after an hour.',
});

// FRONTEND_URL aceita várias origens separadas por vírgula; barra final é ignorada
const allowedOrigins = [process.env.LOCAL_URL, process.env.FRONTEND_URL]
    .filter(Boolean)
    .flatMap((value) => value.split(','))
    .map((url) => url.trim().replace(/\/+$/, ''))
    .filter(Boolean);

const corsOptions = {
    origin: allowedOrigins,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(helmet());

app.use((req, res, next) => {
    if (req.body) {
        mongoSanitize.sanitize(req.body, { replaceWith: '_' });
    }
    if (req.params) {
        mongoSanitize.sanitize(req.params, { replaceWith: '_' });
    }
    next();
});

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('conexao feita');
    })
    .catch((err) => {
        console.error('erro ao conectar', err);
    });

app.use(express.json()); 

const userRoutes = require('./routes/users');
app.use('/api/', limiter);
app.use('/api/users/signup', createAccountLimiter);
app.use('/api/users', userRoutes);

const dashboardRoutes = require('./routes/dashRoutes')
app.use('/api/dashboards', dashboardRoutes)

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
