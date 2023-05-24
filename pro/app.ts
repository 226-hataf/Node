import express from 'express'
import mongoose from 'mongoose';
import router from './routes/blog';
import userrouter from './routes/user';
import User from './models/user'
const app = express();
const PORT=3000;

app.use(express.json());

mongoose.connect('mongodb://127.0.0.1:27017/blog', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
} as mongoose.ConnectOptions)
.then(() => 
{
  console.log('Connected to the MongoDB database.');
})
.catch((error:Error) => 
{
  console.error('Error connecting to the MongoDB database:', error);
});

 app.use(router)
 app.use(userrouter);


 app.listen(PORT, () => {
    console.log('Server is running on port ${PORT}.');
});


