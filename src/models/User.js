const mongoose = require('mongoose');

let Schema = mongoose.Schema;

const UserSchema = new Schema({
    username: {
        type: String,
        required: true,
        trim: true,
    },
    name: { type: String, trim: true, maxlength: 100 },
    password: { type: String, required: true, select: false },
    role: {type: String, enum: ['user', 'admin'], default: 'user'},
    email: { type: String, required: true, unique: true, trim: true },
    // true = PRECISA TROCAR A SENHA ANTES DE USAR O SISTEMA
    mustChangePassword: { type: Boolean, default: false },
    created_at: { type: Date, default: Date.now },
});

UserSchema.virtual('url').get(function () {
    return '/users/' + this._id;
});

module.exports = mongoose.model('User', UserSchema);
