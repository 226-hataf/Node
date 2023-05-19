import mongoose, { Document, Model, Schema } from "mongoose";

interface ITodo extends Document {
  title: string;
  description: string;
  completed: boolean;
  createdat: Date;
  updatedat:Date;
}

const todoSchema: Schema<ITodo> = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  completed: {
    type: Boolean
  },
  createdat:{
    type:Date,
    default: Date.now
  },
  updatedat:{
    type:Date,
    default: Date.now
  }
});

const Todo: Model<ITodo> = mongoose.model<ITodo>("Todo", todoSchema);

export default Todo;
