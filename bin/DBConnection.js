const mongoose = require(`mongoose`);

const url = process.env.MONGODB_URI || 'mongodb://localhost:27017/prepmaster';

async function connectDB() {
  try {
    mongoose.connect(url).then(r => console.log(`mongoDB connected`)).catch(err => console.log(err.message))
  } catch (error) {
    console.error('MongoDB connection error:', error);
    throw error; 
  }
}



module.exports = connectDB;