import { Request, Response, Router,NextFunction } from 'express';
import Blog from '../models/blog';
import {toker} from'./user'
import jwt from 'jsonwebtoken';
import { compare } from 'bcryptjs';
import { Auth } from 'mongodb';
import upload from '../image/img'
export const router = Router();

interface Authreq extends Request {
  user?: any;
}

const authenticateUser = (req: Authreq, res: Response, next: NextFunction) => {
  const token = req.headers.authorization;
  console.log(" Token generated at the time of the login")
  console.log(toker)
 
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized user ' });
  }
 

  try {
    // const decoded = compare(token, toker);
   // const decoded =jwt.(token,toker);
    //const decoded =toker.localeCompare(token)
    //req.user = decoded;
    next();
  }
  
  catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
 
  }
};



interface BlogPost {
  id: number;
  title: string;
  content: string;
  author:string;
  date: Date;
  comments:string;
  tags:string;
  categories:string;
  image: string
}

router.post('/blogs', authenticateUser,upload.single("image"), async (req: Authreq, res: Response) => {
  try {
    console.log('/blogs',req.body)
    const { title,content,author,comments,tags,categories} = req.body as BlogPost;

    if (!title) {
      return res.status(400).json({ error: 'Title  is empty' });
    }
  

    if (!author) {
      return res.status(400).json({ error: 'author is empty' });
    }


    if (!content) {
      return res.status(400).json({ error: 'Content is required' });
    }
    // const resizedImagePromises = [
    //   resizeAndOptimizeImage(imagePath, 800), 
    //   resizeAndOptimizeImage(imagePath, 500), 
    //   resizeAndOptimizeImage(imagePath, 300), 
    // ];

    const newBlog = new Blog({
  
      title,
      content,
      author,
      comments,
      categories,
      tags,
      image :req.file ? req.file.path : '',
    });

    const savedBlog = await newBlog.save();

    res.status(201).json(savedBlog);
  } 
  catch (error) 
  {
    res.status(500).json({ error: 'Error creating a new blog'});
  }
});


router.get('/blogsbyID/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const blog:BlogPost = await Blog.findById(id) as BlogPost;

    if (typeof id !== 'string') {
      return res.status(400).json({ error: 'id must be a number' });
    }

    if (!blog) {
      return res.status(404).json({ error: 'Blog Does nt exits' });
    }

    res.json(blog);
  } catch (error) {
    res.status(500).json({ error: 'Error retrieving blog post' });
  }
});

router.put('/blogsUpdate/:id',authenticateUser, async (req: Authreq, res: Response) => {
  try {
    const id  = req.params.id;
    const { title, content, author,comments,tags,categories } = req.body as BlogPost;

    
    if(typeof id !== 'string') 
    {
      return res.status(400).json({ error: 'id must be a number' });
    }

    if(!title) 
    {
      return res.status(400).json({ error: 'Title  is empty' });
    }

    if(!author)
    {
      return res.status(400).json({ error: 'author is empty' });
    }
    if(!content) 
    {
      return res.status(400).json({ error: 'Content is required' });
    }


    const updatedBlog = await Blog.findByIdAndUpdate(
      id,
      { title, content, author,comments,tags,categories },
      { new: true }
    );

  
    if (!updatedBlog) {
      return res.status(404).json({ error: 'Blog post doesnt exits' });
    }

    res.status(200).json(updatedBlog);
  } catch (error) {
    res.status(500).json({ error: 'Error updating blog post' });
  }
});


router.delete('/delbyID/:id',authenticateUser, async (req: Authreq, res: Response) => {
  try {
   
    const { id } = req.params;

    const deletedBlog:BlogPost = await Blog.findByIdAndDelete(id) as BlogPost;

    if (!deletedBlog) {
      return res.status(404).json({ error: 'Blog post not found' });
    }

    res.json({ message: 'Blog post deleted' });
  } catch (error) {
    console.error('Error deleting blog post:', error);
    res.status(500).json({ error: 'Error deleting blog post' });
  }
});

router.get('/blogsbypage', async (req: Request, res: Response) => {
  try {
    const page: number = Number(req.query.page) || 1;
    const limit: number = Number(req.query.limit) || 10;
    const skip: number = (page - 1) * limit;

    if (!page) {
      return res.status(400).json({ error: 'Invalid page e' });
    }

    if (!limit) {
      return res.status(400).json({ error: 'Invalid' });
    }

    const blogs = await Blog.find()
      .skip(skip)
      .limit(limit)
      .exec();

    res.status(200).json(blogs);
  } catch (error) {
    console.error('Error retrieving blogs:', error);
    res.status(500).json({ error: 'Error retrieving blogs' });
  }
});



router.get('/ascendingDate', async (req: Request, res: Response) => {
  try {
    const blogs:unknown = await Blog.find().sort({ date: 1 }).exec() ;
    res.status(200).json(blogs);
  } 
  catch (error) {
    console.error('Error retrieving blogs:', error);
    res.status(500).json({ error: 'Error No recs exits' });
  }
});


router.get('/descendingDate', async (req: Request, res: Response) => {
  try {

    const blogs:unknown = await Blog.find().sort({ date: -1 }).exec();
    res.status(200).json(blogs);
  } 
  catch (error) {
    console.error('Error ', error);
    res.status(500).json({ error: 'Error' });
  }
});

export default router;










