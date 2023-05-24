import mongoose, { Document, Model, Schema } from "mongoose";

interface UserPost extends Document {
    name: String,
    email:String,
    password:string
  }

  const UserSchema: Schema<UserPost> = new mongoose.Schema({

    name:{
        type:String,
        required:true
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
  });
  
  const User: Model<UserPost> = mongoose.model<UserPost>("User", UserSchema);
  
  export default User;


    