require('dotenv').config();
require('mongoose').set('strictQuery', true);

const express = require('express');
const app = express();

const cors = require('cors');
const cookieParser = require('cookie-parser');
const connectDB = require('./db/connect');

const authRouter = require('./routes/authRoutes');

app.use(cors({
  origin: '*'
}));
app.use(express.json());
app.use(cookieParser(process.env.JWT_SECRET));
app.use('/api/auth', authRouter);

const port = process.env.PORT || 5000;
const start = async () => {
  try {
    await connectDB(process.env.MONGO_URL);
    app.listen(port, () =>
      console.log(`Server is listening on port ${port}...`)
    );
  } catch (error) {
    console.log(error);
  }
};

start();