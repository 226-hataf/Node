import express from 'express'
const app = express();
const PORT=8081;
import {json} from 'body-parser'
import { todoRouter } from './routes/todo';
import mongoose from 'mongoose';
import swaggerJSDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import swaggerDocument from './models/swagger.json'; 


app.use(express.json());
mongoose.connect('mongodb://0.0.0.0:27017', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
} as mongoose.ConnectOptions)
.then(() => {
  console.log('Connected to the MongoDB database.');
})
.catch((error:Error) => {
  console.error('Error connecting to the MongoDB database:', error);
});

app.use(todoRouter);
const swaggerOptions = {
  swaggerDefinition: swaggerDocument,
  apis: [`./routes/todo.ts`], 
} as swaggerJSDoc.Options;

const swaggerSpec = swaggerJSDoc(swaggerOptions);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}.`);
});

