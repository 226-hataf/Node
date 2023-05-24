import mongoose, { Document, Model, Schema } from "mongoose";
import multer, { Multer } from "multer";


interface BlogPost extends Document {
  title: string;
  content: string;
  author: string;
  date: Date;
  comments:string;
  tags:string;
  categories:string;
  image: string;
}

const blogPostSchema: Schema<BlogPost> = new mongoose.Schema({

  title: {
    type: String,
    required: true,
  },
  content: {
    type: String,
    required: true,
  },
  author: {
    type: String,
    required: true,
  },
  date: {
    type: Date,
    default: Date.now,
  },
  comments:{
    type: String
  },

  tags:{
    type: String
  },

  categories:{
    type: String
  },
  image:{
    type: String
  }

});

const Blog: Model<BlogPost> = mongoose.model<BlogPost>("Blog", blogPostSchema);

export default Blog;
