const { Timestamp } = require('mongodb');
const mongoose = require('mongoose')

let Schema = mongoose.Schema

const DashSchema = new Schema({
    title: {
        type: String,
        required: true,
        trim: true,
    },
    iconName: {
        type: String,
        enum: ['sales', 'marketing', 'finance', 'operations', 'hr', 'it', 'customer_service', 'product', 'legal', 'other'],
        required: true,
    },
    description: {
        type: String,
        required: true,
    },
    // 'iframe' = EMBED NA PÁGINA DO DASH | 'link' = ABRE UM ENDEREÇO EXTERNO EM NOVA ABA
    contentType: {
        type: String,
        enum: ['iframe', 'link'],
        default: 'iframe'
    },
    embed: {
        type: String,
        required: function () { return this.contentType !== 'link' },
    },
    link: {
        type: String,
        required: function () { return this.contentType === 'link' },
    },
    isActive: {
        type: Boolean,
        default: true
    },
    // 'all' = TODOS OS USUÁRIOS | 'restricted' = SÓ OS USUÁRIOS EM allowedUsers
    visibility: {
        type: String,
        enum: ['all', 'restricted'],
        default: 'all'
    },
    allowedUsers: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true },
},
    {
        timestamps: true
    }
);

DashSchema.virtual('url').get(function () {
    return '/dash/' + this._id;
})

module.exports = mongoose.model('Dashboard', DashSchema)
