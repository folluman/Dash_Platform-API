const crypto = require('crypto');
const { body } = require('express-validator');

// REGRA ÚNICA DE SENHA (CADASTRO E TROCA DE SENHA USAM A MESMA)
// SE MUDAR AQUI, MUDE TAMBÉM EM front-end/src/services/passwordRules.js
// { optional: true } = CAMPO PODE VIR VAZIO (EX: EDIÇÃO DE USUÁRIO SEM TROCAR A SENHA)
exports.passwordValidator = (field, { optional = false } = {}) =>
    (optional ? body(field).optional({ values: 'falsy' }) : body(field))
        .isString()
        .withMessage('Informe a senha.')
        .trim()
        .isLength({ min: 8 })
        .withMessage('A senha deve ter pelo menos 8 caracteres.')
        .matches(/[A-Za-z]/)
        .withMessage('A senha deve conter pelo menos uma letra.')
        .matches(/[0-9]/)
        .withMessage('A senha deve conter pelo menos um número.');

// SEM CARACTERES QUE SE CONFUNDEM AO LER/DITAR (0/O, 1/l/I)
const LETTERS = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
const DIGITS = '23456789';
const ALPHABET = LETTERS + DIGITS;

// GERA UMA SENHA TEMPORÁRIA ALEATÓRIA (crypto = ALEATORIEDADE SEGURA, AO CONTRÁRIO DO Math.random)
// SEMPRE ATENDE À REGRA: 12 CARACTERES, COM PELO MENOS UMA LETRA E UM NÚMERO
exports.generateTemporaryPassword = (length = 12) => {
    const chars = [
        LETTERS[crypto.randomInt(LETTERS.length)],
        DIGITS[crypto.randomInt(DIGITS.length)],
    ];

    while (chars.length < length) {
        chars.push(ALPHABET[crypto.randomInt(ALPHABET.length)]);
    }

    // EMBARALHA (FISHER-YATES) PARA A LETRA E O NÚMERO NÃO FICAREM SEMPRE NO INÍCIO
    for (let i = chars.length - 1; i > 0; i--) {
        const j = crypto.randomInt(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join('');
};
