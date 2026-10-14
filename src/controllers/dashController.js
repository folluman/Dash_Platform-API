const Dash = require('../models/Dash');
require('dotenv').config();
const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('../models/User');

// FILTRO DE ACESSO: ADMIN VÊ TUDO; USUÁRIO COMUM VÊ OS PÚBLICOS E OS RESTRITOS EM QUE FOI LIBERADO
// (DASHBOARDS ANTIGOS, SEM O CAMPO visibility, CONTAM COMO PÚBLICOS)
async function accessFilter(req) {
    const user = await User.findById(req.user.id).exec();
    if (user && user.role === 'admin') return {};
    return {
        $or: [
            { visibility: { $nin: ['restricted', 'admins'] } },
            { visibility: 'restricted', allowedUsers: req.user.id }
        ]
    };
}

// NORMALIZA OS CAMPOS DE ACESSO QUE VÊM DO FRONT
function parseAccess(body) {
    const visibility = ['restricted', 'admins'].includes(body.visibility) ? body.visibility : 'all';
    const allowedUsers = visibility === 'restricted' && Array.isArray(body.allowedUsers)
        ? [...new Set(body.allowedUsers)].filter((id) => mongoose.isValidObjectId(id))
        : [];
    return { visibility, allowedUsers };
}

// DOMÍNIOS PERMITIDOS PARA LINKS (OPCIONAL). EX NO .env:
// ALLOWED_LINK_DOMAINS=app.powerbi.com,lookerstudio.google.com
// VAZIO = ACEITA QUALQUER DOMÍNIO, DESDE QUE SEJA https
const ALLOWED_LINK_DOMAINS = (process.env.ALLOWED_LINK_DOMAINS || '')
    .split(',')
    .map((domain) => domain.trim().toLowerCase())
    .filter(Boolean);

// VALIDA O LINK E DEVOLVE A VERSÃO NORMALIZADA (OU null SE FOR INSEGURO)
function validateLink(value) {
    if (typeof value !== 'string' || value.length > 2048) return null;

    let url;
    try {
        url = new URL(value.trim());
    } catch {
        return null;
    }

    // SÓ https: BLOQUEIA javascript:, data:, file:, http: ETC.
    if (url.protocol !== 'https:') return null;
    // BLOQUEIA LINKS ENGANOSOS COMO https://app.powerbi.com@site-malicioso.com
    if (url.username || url.password) return null;

    if (ALLOWED_LINK_DOMAINS.length > 0) {
        const host = url.hostname.toLowerCase();
        const allowed = ALLOWED_LINK_DOMAINS.some((domain) => host === domain || host.endsWith(`.${domain}`));
        if (!allowed) return null;
    }

    return url.href;
}

// NORMALIZA O CONTEÚDO DO DASH: OU IFRAME OU LINK, NUNCA OS DOIS
function parseContent(body) {
    const contentType = body.contentType === 'link' ? 'link' : 'iframe';

    if (contentType === 'link') {
        const link = validateLink(body.link);
        if (!link) {
            const domains = ALLOWED_LINK_DOMAINS.length ? ` Domínios permitidos: ${ALLOWED_LINK_DOMAINS.join(', ')}.` : '';
            return { error: `Link inválido. Use um endereço completo começando com https://.${domains}` };
        }
        return { contentType, link, embed: undefined };
    }

    const embed = typeof body.embed === 'string' ? body.embed.trim() : '';
    if (!embed) {
        return { error: 'O código do iframe deve ser informado.' };
    }
    return { contentType, embed, link: undefined };
}

exports.dash_list = asyncHandler(async (req, res, next) => {
    const dashs = await Dash.find(await accessFilter(req)).exec();
    res.json(dashs)
})

exports.dash_create_post = [
    body('title')
        .trim()
        .isLength({ min: 1 })
        .withMessage('Title must be specified.')
        .escape()
        .matches(/^[a-zA-Z0-9À-ú\s]+$/)
        .withMessage('Title must contain only letters, numbers, and spaces.'),
    body('description')
        .trim()
        .isLength({ min: 1 })
        .withMessage('Description must be specified.'),
    body('isActive')
        .isBoolean()
        .withMessage('isActive must be a boolean (true or false).'),
    body('iconName')
        .trim()
        .isLength({ min: 1 })
        .withMessage('Icon name must be specified.')
        .escape(),

    asyncHandler(async(req, res, next) => {
        const title = await Dash.findOne({ title: req.body.title }).exec()

        if (title) {
            return res.status(400).json({error: 'Title already exists!'})
        }

        const errors = validationResult(req);

        const access = parseAccess(req.body);
        if (access.visibility === 'restricted' && access.allowedUsers.length === 0) {
            return res.status(400).json({ error: 'Selecione ao menos um usuário.' })
        }

        const content = parseContent(req.body);
        if (content.error) {
            return res.status(400).json({ error: content.error })
        }

        const dash = new Dash({
            user_id: req.user.id,
            title: req.body.title,
            description: req.body.description,
            contentType: content.contentType,
            embed: content.embed,
            link: content.link,
            isActive: req.body.isActive,
            iconName: req.body.iconName,
            visibility: access.visibility,
            allowedUsers: access.allowedUsers
        })

        if(!errors.isEmpty()) {
            return res.status(400).json({
                erro: 'Validation failed',
                details: errors.array()
            })
        }

        await dash.save();
        res.status(201).json({ message: 'Dash created sucessfully!'})
    })
]

exports.dash_content = asyncHandler(async (req, res, next) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(404).json({ error: 'Dash não encontrado' })
    }

    // SE O USUÁRIO NÃO TEM ACESSO, RESPONDE 404 PARA NÃO REVELAR QUE O DASH EXISTE
    const dash = await Dash.findOne({ _id: req.params.id, ...(await accessFilter(req)) }).exec();

    if (!dash) {
        return res.status(404).json({ error: 'Dash não encontrado' })
    }

    res.json(dash)
})

// ATUALIZAR O DASHBOARD
exports.dash_update = asyncHandler(async(req, res) => {
    const {id} = req.params
    const dash = await Dash.findById(id)

    if(!dash) {
        return res.status(404).json({error: 'Não foi possível atualizar o dashboard'})
    }

    // SÓ ESSES CAMPOS PODEM SER ALTERADOS DIRETO. ANTES ERA Object.assign(dash, req.body),
    // QUE DEIXAVA O BODY SOBRESCREVER QUALQUER CAMPO (user_id, link SEM VALIDAÇÃO...)
    const editableFields = ['title', 'description', 'iconName', 'isActive'];
    editableFields.forEach((field) => {
        if (field in req.body) dash[field] = req.body[field];
    });

    if ('contentType' in req.body || 'embed' in req.body || 'link' in req.body) {
        const content = parseContent({ contentType: dash.contentType, ...req.body });
        if (content.error) {
            return res.status(400).json({ error: content.error })
        }
        dash.contentType = content.contentType;
        dash.embed = content.embed;
        dash.link = content.link;
    }

    if ('visibility' in req.body) {
        const access = parseAccess(req.body);
        if (access.visibility === 'restricted' && access.allowedUsers.length === 0) {
            return res.status(400).json({ error: 'Selecione ao menos um usuário.' })
        }
        dash.visibility = access.visibility;
        dash.allowedUsers = access.allowedUsers;
    }

    await dash.save()

    res.status(200).json(dash)
})

exports.dash_delete = asyncHandler(async (req, res) => {
    const {id} = req.params
    const dash = await Dash.findByIdAndDelete(id)
    if(!dash) return res.status(404).json({ error: 'Dash não encontrado'})
    res.status(200).json({message: 'Dashboard deletado com sucesso!'})
})
