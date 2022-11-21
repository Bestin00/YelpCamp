const mongoose=require('mongoose');
const passportLocalMongoose=require('passport-local-mongoose');
//const Schema=mongoose.Schema;


const UserSchema=new mongoose.Schema({
    email:{
        type:String,
        required:true,
        unique:true
    }
});

UserSchema.plugin(passportLocalMongoose);//This is going to add field for username password to userSchema 
  

module.exports=mongoose.model('User',UserSchema);