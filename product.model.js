const mongoose = require('mongoose');


const ProductSchema = mongoose.Schema(
    {
        name: {
            type: String,
            required: [true, "Please enter Customer name"]
        },

        dob: {
            type: Date,
            required: true,
        },

        income: {
            type: Number,
            required: true
        }
    },
    {
        timestamps: true
    }
);

const Product = mongoose.model("Product", ProductSchema);

module.exports = Product;