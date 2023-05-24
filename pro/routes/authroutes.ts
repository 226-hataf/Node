// import { Request, Response, NextFunction, Router } from 'express';
// import jwt from 'jsonwebtoken';
// import Blog from '../models/blog';
// export const router = Router();

// interface Authreq extends Request {
//   user?: any;
// }

// const authenticateUser = (req: Authreq, res: Response, next: NextFunction) => {
//   const token = req.headers.authorization;

//   if (!token) {
//     return res.status(401).json({ error: 'Unauthorized user ' });
//   }

//   try {
//     const decoded = jwt.verify(token, 'Your token');
//     req.user = decoded;
//     next();
//   } catch (error) {
//     return res.status(401).json({ error: 'Invalid token' });
//   }
// };

// interface BlogPost {
//   title: string;
//   content: string;
//   author: string;
//   date: Date;
// }


// router.post('/blogs', authenticateUser, async (req: Authreq, res: Response) => {
//   try {

//     const { userId } = req.user;
//     const { title, content, author }: BlogPost = req.body as BlogPost;

   
//     const newBlog = new Blog({
//       title,
//       content,
//       author,
//       userId, 
//     });

//     const savedBlog = await newBlog.save();

//     res.status(201).json(savedBlog);
//   } catch (error) {
//     res.status(500).json({ error: 'Error creating a new blog' });
//   }
// });


// router.put('/blogsUpdateer/:id', authenticateUser, async (req:Authreq, res: Response) => {
//   try {
    
//     const { userId } = req.user;
//     const id = req.params.id;
//     const { title, content, author }: BlogPost = req.body as BlogPost;

//     const updatedBlog = await Blog.findOneAndUpdate(
//       { _id: id, userId },
//       { title, content, author },
//       { new: true }
//     );

//     if (!updatedBlog) {
//       return res.status(404).json({ error: 'Blog post does not exist' });
//     }

//     res.status(200).json(updatedBlog);
//   } catch (error) {
//     res.status(500).json({ error: 'Error updating blog post' });
//   }
// });


// router.delete('/delbyID/:id', authenticateUser, async (req: Authreq, res: Response) => {
//   try {
  
//     const { userId } = req.user;
//     const { id } = req.params;

//     const deletedBlog = await Blog.findOneAndDelete({ _id: id, userId });

//     if (!deletedBlog) {
//       return res.status(404).json({ error: 'Blog post not found' });
//     }

//     res.json({ message: 'Blog post deleted' });
//   } catch (error) {
//     console.error('Error deleting blog post:', error);
//     res.status(500).json({ error: 'Error deleting blog post' });
//   }
// });

// export default router;
