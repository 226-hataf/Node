import express, { Request, Response } from 'express';
import Todo from '../models/todo';
import { body, validationResult } from 'express-validator';
import { authenticate } from '../middleware/authenticate'
import { title } from 'process';
const router = express.Router();
interface TodoRequestBody {
  title: string;
  description: string;
  completed: boolean;
  createdat: Date;
  updatedat: Date;
}

router.post('/todos', async (req: Request, res: Response) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, description, completed, createdat, updatedat } = req.body as TodoRequestBody;

    if (!title) {
      return res.status(400).json({ error: 'Title  is empty' });
    }

    if (!description) {
      return res.status(400).json({ error: 'Description  is empty' });
    }

    const newTodo = new Todo({
      title,
      description,
      completed,
      createdat,
      updatedat
    });

    const savedTodo = await newTodo.save();

    res.status(201).json(savedTodo);
  } catch (error) {
    res.status(500).json({ error: 'Error creating todo' });
  }
});

interface Pagination {
  page?: Number;
  limit?:Number;
  startId?:Number;
  endId?:Number;
}

router.get('/todosAllData', async (req: Request, res: Response) => {
  try {
    const { page = 1, limit = 10, startId, endId }:Pagination= req.query;

    const query: any= {};


    if (startId) {
      query._id = { $gte: startId };
    }

    if (endId) {
      if (query._id) {
        query._id.$lte = endId;
      } else {
        query._id = { $lte: endId };
      }
    }
    const totalTodos = await Todo.countDocuments(query);
    const skip = (Number(page) - 1) * Number(limit);

    const todos = await Todo.find(query)
      .skip(skip)
      .limit(Number(limit));

    res.status(200).json({
      todos,
      currentPage: page,
      totalPages: Math.ceil(totalTodos / Number(limit)),
    });
  } catch (error) {
    console.error('Error retrieving todos:', error);
    res.status(500).json({ error: 'Error retrieving todos' });
  }
});

interface Tododel{
  todoId:string,
  id:string
}

router.get('/todosbyID/:id', async (req: Request<Tododel>, res: Response) => {
  try {
    const todoID = req.params.id;
    const todos = await Todo.findById(todoID);

    if (!todos) {
      return res.status(404).json({ error: 'id not found' });
    }

    res.status(200).json(todos);
  } catch (error) {
    console.error('Error retrieving todo:', error);
    res.status(500).json({ error: 'Id field is empty or invalid format'});
  }
});


router.put('/todosbyID/:id', async (req: Request<Tododel>, res: Response) => {
  try {
    const todoID = req.params.id;
    const { title, description, completed } = req.body as TodoRequestBody 

    const updatedTodo = await Todo.findByIdAndUpdate(
      todoID, { title, description, completed },
      { new: true }
    );

    if (!updatedTodo) {
      return res.status(404).json({ error: 'Id doiesnt exists' });
    }

    res.status(200).json(updatedTodo);
  } catch (error) {
    console.error('ID Field cant be empty', error);
    res.status(500).json({ error: 'ID Field cant be empty' });
  }
});


router.delete('/delbyID/:id', async (req: Request<Tododel>, res: Response) => {
  try {
    const todoId = req.params.id;

    const deletedTodo = await Todo.findByIdAndDelete(todoId);

    if (!deletedTodo) {
      return res.status(404).json({ error: 'id does not exits'});
    }

    res.status(200).json({ message: 'Deleted '});
  }
  catch (error) {
    console.error('Error deleting todo:', error);
    res.status(500).json({ error: 'ID field cant be empty' });
  }
});

export { router as todoRouter };


