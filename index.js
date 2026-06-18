const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    console.log('🎯 Successfully connected to MongoDB!');

    const db = client.db('ticketBariDB');
    const ticketsCollection = db.collection('tickets');
    const usersCollection = db.collection('users');
    const bookingsCollection = db.collection('bookings');

    app.get('/', (req, res) => {
      res.send('TicketBari Server is running smoothly...');
    });

    app.get('/tickets', async (req, res) => {
      try {
        const cursor = ticketsCollection.find({});
        const result = await cursor.toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error fetching tickets', error });
      }
    });
  } finally {
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`🚀 TicketBari Server is zooming on port ${port}`);
});
