import { Request, Response, Router } from 'express';
import Blog from '../models/user'
import jwt from 'jsonwebtoken'
import {  compare, hash } from 'bcryptjs';
import User from '../models/user';
import { sign } from 'jsonwebtoken';
import { Document} from 'mongoose';


export const userrouter = Router();

interface UserPost extends Document{
    name:string,
    email:string,
    password:string
}

userrouter.post('/registeration', async (req: Request, res: Response) => {
    try {
      const { name, email, password }:UserPost = req.body as UserPost;
      const existingUser:UserPost = await User.findOne({ email }) as UserPost;
      
      if(!name)
      {
        console.log("Name fieold is empty")
      }

      if(!email)
      {
        console.log("Email field is empty")
      }

      if(!password)
      {
        console.log("Password field cant be empty")
      }


      if (existingUser) 
      {
        return res.status(400).json({ error: 'Email All ready registered ' });
      }
  
      const hashedPassword:string = await hash(password, 10);
  
      const newUser:UserPost = new User({ name, email, password: hashedPassword }) as UserPost;
      await newUser.save();
  
      res.json(newUser);
    }
     catch (error) 
     {
      console.error(error);
      res.status(500).json({ error: 'Failed to register user' });
    }
  }); 
  var  toker:string;

  userrouter.post('/login', async (req: Request, res: Response) => {
    try {
      const { email, password }:UserPost = req.body;
      
      if(!password)
      {
        console.log("Password field is empty")
      }

      if(!email)
      {
        console.log("Email field is empty")
      }

      const user:UserPost| null = await User.findOne({ email });

      if (!user) 
      {
        return res.status(404).json({ error: 'User not found' });
      }
  
      const isPasswordValid:boolean = await compare(password, user.password);
      if (!isPasswordValid) 
      {
        return res.status(401).json({ error: 'Invalid password' });
      }
  
      const token:string = sign({ userId: user._id }, 'secretKey');
      toker = token;

      res.json({ token, message: 'Logged in Welcome' })
    } 
    catch (error) 
    {
      console.error(error);
      res.status(500).json({ error: 'Failed to authenticate user' });
    }

    console.log(toker)
   
  });

  export {toker};
  userrouter.post('/resetPassword', async (req: Request, res: Response) => {
    try {
      const { email, password }: UserPost= req.body as UserPost;
  
      if (!password) {
        console.log("Password field is empty");
      }
  
      if (!email) {
        console.log("Email field is empty");
      }
  
      const user: UserPost | null = await User.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      const hashedPassword: string = await hash(password, 1);
      user.password = hashedPassword;
      await user.save();
  
      res.json({ message: 'Password reset successful' });
    } 
    
    catch (error) 
    {
      console.error(error);
      res.status(500).json({ error: 'Failed to reset password' });
    }
  });



  export default userrouter;
