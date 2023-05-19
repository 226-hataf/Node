import express, { Request, Response } from 'express';
import Todo from '../models/todo';
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
    const { title, description, completed, createdat, updatedat } = req.body as TodoRequestBody;

    if (!title) {
      return res.status(400).json({ error: 'Title  is empty' });
    }
    if (!description) {
      return res.status(400).json({ error: 'Description  is empty' });
    }
    if (typeof completed !== 'boolean') {
      return res.status(400).json({ error: 'Completed must be a boolean' });
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

router.get('/todosAllData', async (req: Request, res: Response) => {
  try {
    const page: number = Number(req.query.page) || 1;
    const limit: number = Number(req.query.limit) || 10;
    const skip: number = (page - 1) * limit;

    
    if (!page) {
      return res.status(400).json({ error: 'PAge  is empty' });
    }
      if (!limit) {
      return res.status(400).json({ error: 'Limit  is empty' });
    }

    const todos = await Todo.find()
      .skip(skip)
      .limit(limit)
      .exec();

    res.status(200).json(todos);
  } catch (error) {
    console.error('Error retrieving todos:', error);
    res.status(500).json({ error: 'Cant be empty' });
  }
});




router.get('/GettodosbyID/:id', async (req: Request, res: Response) => {
  try {
    const todoID:string = req.params.id;

    const todos:TodoRequestBody = await Todo.findById(todoID) as TodoRequestBody;

    if (!todos) {
      return res.status(404).json({ error: 'id not found' });
    }

    res.status(200).json(todos);
  } catch (error) {
    console.error('Error retrieving todo:', error);
    res.status(500).json({ error: 'Id field is empty or invalid format'});
  }
});


router.put('/todosbyID/:id', async (req: Request, res: Response) => {
  try {
    const todoID:string= req.params.id;
    const { title, description, completed } = req.body as TodoRequestBody

    if (!title) {
      return res.status(400).json({ error: 'Title  is empty' });
    }
    if (!description) {
      return res.status(400).json({ error: 'Description  is empty' });
    }
    if (typeof completed !== 'boolean') {
      return res.status(400).json({ error: 'Completed must be a boolean' });
    }

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



router.delete('/delbyID/:id', async (req: Request, res: Response) => {
  try {
    const todoId:string = req.params.id;
    const deletedTodo:TodoRequestBody = await Todo.findByIdAndDelete(todoId) as TodoRequestBody;

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