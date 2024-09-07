const mongoose  = require(`mongoose`);


const userSchema = new mongoose.Schema({

    username:{
        type:String,
        required:true,
    },
    email:{
        type: String,
        required:true,
        unique:true,
        trim:true,
        lowercase:true
    },
    password:{
        type:String,
        required:true
    },
    roles:{
        type:[String],
        default:[`student`],
        enum:[`student`,`teacher`,`admin`]
    },
    refreshToken: {
        token: { 
            type: String, 
        },
        expiresAt: { 
            type: Date 
        }
      },
    createdAt:{
        type:Date,
        default: Date.now
    }

})


const User = mongoose.model(`users`,userSchema);
module.exports = User;