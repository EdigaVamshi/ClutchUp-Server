const mongoose=require('mongoose');

const valoMatchSchema = new mongoose.Schema({
    mode:{
        type: String,
        required: true
    },
    prizePool:{
        type: Number,
        required: true
    },
    fee:{
        type: Number,
        required: true
    },
    lobby:{
        type: String,
        required: true
    }
});

module.exports=mongoose.model('ValorantMatch', valoMatchSchema);