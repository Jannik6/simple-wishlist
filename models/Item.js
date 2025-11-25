const mongoose = require('mongoose'); // Ensure mongoose is imported

const itemSchema = new mongoose.Schema({
    name: String,
    price: Number,
    url: String,
    imageUrl: String,
    purchased: { type: Boolean, default: false },
    priority: { type: Number, default: 0 },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});

const Item = mongoose.model('Item', itemSchema);

module.exports = Item;
