const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: [
      'https://ticket-bari-client-one.vercel.app',
      'http://localhost:3000',
    ],
    credentials: true,
  }),
);
app.use(express.json());

const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send({ message: 'Unauthorized!' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: 'Forbidden!' });
    req.decoded = decoded;
    next();
  });
}

function isDeparturePassed(date, time) {
  if (!date) return false;
  const target = new Date(`${date}T${time || '00:00'}`).getTime();
  return Date.now() > target;
}

async function run() {
  try {
    await client.connect();
    console.log('✅ Connected to MongoDB!');

    const db = client.db('ticketBariDB');
    const ticketsCollection = db.collection('tickets');
    const usersCollection = db.collection('users');
    const bookingsCollection = db.collection('bookings');
    const transactionsCollection = db.collection('transactions');

    const verifyAdmin = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.decoded.email });
      if (user?.role !== 'admin')
        return res.status(403).send({ message: 'Admin access required.' });
      next();
    };

    const verifyVendor = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.decoded.email });
      if (user?.role !== 'vendor' && user?.role !== 'admin')
        return res.status(403).send({ message: 'Vendor access required.' });
      next();
    };

    // ══════════════════════════════════════════
    // AUTH ENDPOINTS
    // ══════════════════════════════════════════

    app.post('/register', async (req, res) => {
      try {
        const { name, email, password, role } = req.body;
        const existing = await usersCollection.findOne({ email });
        if (existing)
          return res.status(400).send({ message: 'Email already registered!' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const safeRole = role === 'admin' ? 'user' : role || 'user';

        const newUser = {
          name,
          email,
          password: hashedPassword,
          role: safeRole,
          isFraud: false,
          photoURL: '',
          createdAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);
        res.status(201).send({ success: true, insertId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Registration failed', error });
      }
    });

    app.post('/login', async (req, res) => {
      try {
        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: 'User not found!' });
        if (user.isFraud)
          return res.status(403).send({ message: 'Account flagged as fraud.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
          return res.status(401).send({ message: 'Invalid credentials!' });

        const token = jwt.sign(
          { email: user.email, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '7d' },
        );

        res.send({
          success: true,
          token,
          user: {
            name: user.name,
            email: user.email,
            role: user.role,
            photoURL: user.photoURL || '',
          },
        });
      } catch (error) {
        res.status(500).send({ message: 'Login failed', error });
      }
    });

    app.post('/auth/social-sync', async (req, res) => {
      try {
        const { name, email, photoURL } = req.body;
        let user = await usersCollection.findOne({ email });

        if (!user) {
          const result = await usersCollection.insertOne({
            name,
            email,
            role: 'user',
            isFraud: false,
            photoURL: photoURL || '',
            createdAt: new Date(),
          });
          user = await usersCollection.findOne({ _id: result.insertedId });
        }

        if (user.isFraud)
          return res.status(403).send({ message: 'Account flagged as fraud.' });

        const token = jwt.sign(
          { email: user.email, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '7d' },
        );

        res.send({
          success: true,
          token,
          user: {
            name: user.name,
            email: user.email,
            role: user.role,
            photoURL: user.photoURL || '',
          },
        });
      } catch (error) {
        res.status(500).send({ message: 'Social sync failed', error });
      }
    });

    app.post('/seed/admin', async (req, res) => {
      try {
        const { name, email, password, secretKey } = req.body;
        if (secretKey !== process.env.SEED_SECRET)
          return res.status(403).send({ message: 'Invalid seed key.' });

        const existing = await usersCollection.findOne({ email });
        if (existing) {
          await usersCollection.updateOne(
            { email },
            { $set: { role: 'admin' } },
          );
          return res.send({
            success: true,
            message: 'Existing user promoted to admin.',
          });
        }

        const hashed = await bcrypt.hash(password, 10);
        await usersCollection.insertOne({
          name,
          email,
          password: hashed,
          role: 'admin',
          isFraud: false,
          photoURL: '',
          createdAt: new Date(),
        });
        res
          .status(201)
          .send({ success: true, message: 'Admin created successfully.' });
      } catch (error) {
        res.status(500).send({ message: 'Seed failed', error });
      }
    });

    // ══════════════════════════════════════════
    // TICKET ENDPOINTS
    // ══════════════════════════════════════════

    app.get('/tickets/advertised', async (req, res) => {
      try {
        const result = await ticketsCollection
          .find({
            advertised: true,
            status: 'approved',
            isHidden: { $ne: true },
          })
          .limit(6)
          .toArray();
        res.send(result);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error loading advertised tickets', error });
      }
    });

    app.get('/tickets/latest', async (req, res) => {
      try {
        const result = await ticketsCollection
          .find({ status: 'approved', isHidden: { $ne: true } })
          .sort({ _id: -1 })
          .limit(8)
          .toArray();
        res.send(result);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error loading latest tickets', error });
      }
    });

    app.get('/tickets/all', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const result = await ticketsCollection
          .find({})
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error loading all tickets', error });
      }
    });

    app.get('/tickets/vendor', verifyJWT, verifyVendor, async (req, res) => {
      try {
        const email = req.query.email || req.decoded.email;
        if (req.decoded.role === 'vendor' && email !== req.decoded.email) {
          return res.status(403).send({ message: 'Forbidden.' });
        }
        const result = await ticketsCollection
          .find({ vendorEmail: email })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error loading vendor tickets', error });
      }
    });

    app.get('/tickets', async (req, res) => {
      try {
        const {
          from,
          to,
          type,
          sortBy,
          page = 1,
          limit = 6,
          email,
        } = req.query;

        if (email) {
          const result = await ticketsCollection
            .find({ vendorEmail: email })
            .sort({ createdAt: -1 })
            .toArray();
          return res.send({ tickets: result, total: result.length, pages: 1 });
        }

        let query = { status: 'approved', isHidden: { $ne: true } };
        if (from) query.from = { $regex: from, $options: 'i' };
        if (to) query.to = { $regex: to, $options: 'i' };
        if (type && type !== 'All Types') query.type = type;

        let sortOptions = {};
        if (sortBy === 'Price: Low to High') sortOptions.price = 1;
        if (sortBy === 'Price: High to Low') sortOptions.price = -1;

        const skip = (Number(page) - 1) * Number(limit);
        const total = await ticketsCollection.countDocuments(query);
        const result = await ticketsCollection
          .find(query)
          .sort(sortOptions)
          .skip(skip)
          .limit(Number(limit))
          .toArray();

        res.send({
          tickets: result,
          total,
          pages: Math.ceil(total / Number(limit)),
        });
      } catch (error) {
        res.status(500).send({ message: 'Error fetching tickets', error });
      }
    });

    app.get('/tickets/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = ObjectId.isValid(id)
          ? { _id: new ObjectId(id) }
          : { id: Number(id) };
        const result = await ticketsCollection.findOne(query);
        if (!result)
          return res.status(404).send({ message: 'Ticket not found.' });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error loading ticket', error });
      }
    });

    app.post('/tickets', verifyJWT, verifyVendor, async (req, res) => {
      try {
        const vendor = await usersCollection.findOne({
          email: req.decoded.email,
        });
        if (vendor?.isFraud)
          return res
            .status(403)
            .send({ message: 'Fraud vendors cannot add tickets.' });

        const newTicket = {
          ...req.body,
          price: Number(req.body.price),
          seats: Number(req.body.seats),
          status: 'pending',
          advertised: false,
          isHidden: false,
          createdAt: new Date(),
        };

        const result = await ticketsCollection.insertOne(newTicket);
        res.status(201).send({ success: true, insertId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Error creating ticket', error });
      }
    });

    app.patch('/tickets/:id', verifyJWT, verifyVendor, async (req, res) => {
      try {
        const id = req.params.id;
        const ticket = await ticketsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!ticket)
          return res.status(404).send({ message: 'Ticket not found.' });

        if (
          req.decoded.role !== 'admin' &&
          ticket.vendorEmail !== req.decoded.email
        ) {
          return res
            .status(403)
            .send({ message: 'You can only edit your own tickets.' });
        }

        const updateData = { ...req.body };
        delete updateData._id;
        delete updateData.vendorEmail;

        const result = await ticketsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              ...updateData,
              price: Number(updateData.price),
              seats: Number(updateData.seats),
              updatedAt: new Date(),
            },
          },
        );
        res.send({ success: true, result });
      } catch (error) {
        res.status(500).send({ message: 'Error updating ticket', error });
      }
    });

    app.patch(
      ['/tickets/:id/status', '/tickets/status/:id'],
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const { status } = req.body;
          const result = await ticketsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status } },
          );
          res.send({ success: true, result });
        } catch (error) {
          res
            .status(500)
            .send({ message: 'Error updating ticket status', error });
        }
      },
    );

    app.patch(
      ['/tickets/:id/advertise', '/tickets/advertise/:id'],
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const { advertised } = req.body;

          if (advertised === true) {
            const count = await ticketsCollection.countDocuments({
              advertised: true,
            });
            if (count >= 6)
              return res
                .status(400)
                .send({ message: 'Max 6 tickets can be advertised.' });
          }

          const result = await ticketsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { advertised } },
          );
          res.send({ success: true, result });
        } catch (error) {
          res.status(500).send({ message: 'Error toggling advertise', error });
        }
      },
    );

    app.delete('/tickets/:id', verifyJWT, verifyVendor, async (req, res) => {
      try {
        const ticket = await ticketsCollection.findOne({
          _id: new ObjectId(req.params.id),
        });
        if (!ticket)
          return res.status(404).send({ message: 'Ticket not found.' });

        if (
          req.decoded.role !== 'admin' &&
          ticket.vendorEmail !== req.decoded.email
        ) {
          return res
            .status(403)
            .send({ message: 'You can only delete your own tickets.' });
        }

        const result = await ticketsCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });
        res.send({ success: true, result });
      } catch (error) {
        res.status(500).send({ message: 'Error deleting ticket', error });
      }
    });

    // ══════════════════════════════════════════
    // BOOKING ENDPOINTS
    // ══════════════════════════════════════════

    app.post('/bookings', verifyJWT, async (req, res) => {
      try {
        const { ticketId, quantity } = req.body;

        if (!ticketId)
          return res.status(400).send({ message: 'ticketId is required.' });

        const ticketQuery = ObjectId.isValid(ticketId)
          ? { _id: new ObjectId(ticketId) }
          : { id: Number(ticketId) };
        const ticket = await ticketsCollection.findOne(ticketQuery);

        if (!ticket)
          return res.status(404).send({ message: 'Ticket not found.' });
        if (ticket.status !== 'approved' || ticket.isHidden)
          return res
            .status(400)
            .send({ message: 'This ticket is not available for booking.' });
        if (!ticket.seats || ticket.seats <= 0)
          return res
            .status(400)
            .send({ message: 'No seats left for this ticket.' });

        const qty = Number(quantity) || 0;
        if (qty <= 0)
          return res.status(400).send({ message: 'Invalid booking quantity.' });
        if (qty > ticket.seats)
          return res
            .status(400)
            .send({ message: 'Booking quantity exceeds available seats.' });
        if (isDeparturePassed(ticket.date, ticket.time))
          return res
            .status(400)
            .send({ message: 'Departure time has already passed.' });

        const booking = {
          ...req.body,
          userEmail: req.decoded.email,
          status: 'pending',
          createdAt: new Date(),
        };

        const result = await bookingsCollection.insertOne(booking);
        res.status(201).send({ success: true, insertId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Booking failed', error });
      }
    });

    app.get('/bookings/vendor', verifyJWT, verifyVendor, async (req, res) => {
      try {
        const email = req.query.email || req.decoded.email;
        const vendorTickets = await ticketsCollection
          .find({ vendorEmail: email })
          .toArray();
        if (vendorTickets.length === 0) return res.send([]);

        const ticketIds = vendorTickets.map(t => t._id.toString());
        const bookings = await bookingsCollection
          .find({ ticketId: { $in: ticketIds } })
          .sort({ createdAt: -1 })
          .toArray();

        res.send(bookings);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error fetching vendor bookings', error });
      }
    });

    app.get('/bookings', verifyJWT, async (req, res) => {
      try {
        const email = req.decoded.email;
        const query = req.decoded.role === 'admin' ? {} : { userEmail: email };

        const vendorCheck = await usersCollection.findOne({
          email: req.decoded.email,
        });
        if (vendorCheck?.role === 'vendor') {
          const myTickets = await ticketsCollection
            .find({ vendorEmail: req.decoded.email })
            .toArray();
          const ids = myTickets.map(t => t._id.toString());
          const vendorRequests = await bookingsCollection
            .find({ ticketId: { $in: ids } })
            .sort({ createdAt: -1 })
            .toArray();
          return res.send(vendorRequests);
        }

        const result = await bookingsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error fetching bookings', error });
      }
    });

    app.patch(
      ['/bookings/:id/status', '/bookings/:id'],
      verifyJWT,
      verifyVendor,
      async (req, res) => {
        try {
          const { status } = req.body;
          const booking = await bookingsCollection.findOne({
            _id: new ObjectId(req.params.id),
          });
          if (!booking)
            return res.status(404).send({ message: 'Booking not found.' });

          if (req.decoded.role !== 'admin') {
            const ticketQuery = ObjectId.isValid(booking.ticketId)
              ? { _id: new ObjectId(booking.ticketId) }
              : { id: Number(booking.ticketId) };
            const ticket = await ticketsCollection.findOne(ticketQuery);
            if (!ticket || ticket.vendorEmail !== req.decoded.email) {
              return res
                .status(403)
                .send({ message: 'You can only manage your own bookings.' });
            }
          }

          const result = await bookingsCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { status, updatedAt: new Date() } },
          );
          res.send({ success: true, result });
        } catch (error) {
          res
            .status(500)
            .send({ message: 'Error updating booking status', error });
        }
      },
    );

    app.delete('/bookings/:id', verifyJWT, async (req, res) => {
      try {
        const booking = await bookingsCollection.findOne({
          _id: new ObjectId(req.params.id),
        });
        if (!booking)
          return res.status(404).send({ message: 'Booking not found.' });

        if (booking.userEmail !== req.decoded.email)
          return res
            .status(403)
            .send({ message: 'You can only cancel your own bookings.' });
        if (booking.status !== 'pending')
          return res
            .status(400)
            .send({ message: 'Only pending bookings can be cancelled.' });

        const result = await bookingsCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });
        res.send({ success: true, result });
      } catch (error) {
        res.status(500).send({ message: 'Error cancelling booking', error });
      }
    });

    // ══════════════════════════════════════════
    // PAYMENT ENDPOINTS
    // ══════════════════════════════════════════

    // ✅ NEW: Stripe Checkout Session
    app.post('/create-checkout-session', verifyJWT, async (req, res) => {
      try {
        const { price, ticketTitle, quantity, bookingId, ticketId } = req.body;

        // departure check
        if (ticketId) {
          const ticketQuery = ObjectId.isValid(ticketId)
            ? { _id: new ObjectId(ticketId) }
            : { id: Number(ticketId) };
          const ticket = await ticketsCollection.findOne(ticketQuery);
          if (ticket && isDeparturePassed(ticket.date, ticket.time)) {
            return res
              .status(400)
              .send({ message: 'Cannot pay — departure time has passed.' });
          }
        }

        const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          mode: 'payment',
          line_items: [
            {
              price_data: {
                currency: 'usd',
                product_data: {
                  name: ticketTitle || 'Travel Ticket',
                  description: `Quantity: ${quantity}`,
                },
                unit_amount: Math.round(
                  (Number(price) / Number(quantity)) * 100,
                ),
              },
              quantity: Number(quantity),
            },
          ],
          success_url: `${process.env.CLIENT_URL}/payment/success?bookingId=${bookingId}&ticketId=${ticketId}&amount=${price}&session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.CLIENT_URL}/dashboard`,
          metadata: {
            bookingId,
            ticketId,
            userEmail: req.decoded.email,
            quantity: String(quantity),
          },
        });

        res.send({ url: session.url, sessionId: session.id });
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Checkout session failed', error: error.message });
      }
    });

    app.post('/create-payment-intent', verifyJWT, async (req, res) => {
      try {
        const { price, ticketId } = req.body;
        if (!price || isNaN(price))
          return res.status(400).send({ message: 'Invalid price.' });

        if (ticketId) {
          const ticketQuery = ObjectId.isValid(ticketId)
            ? { _id: new ObjectId(ticketId) }
            : { id: Number(ticketId) };
          const ticket = await ticketsCollection.findOne(ticketQuery);
          if (ticket && isDeparturePassed(ticket.date, ticket.time)) {
            return res
              .status(400)
              .send({ message: 'Cannot pay — departure time has passed.' });
          }
        }

        const paymentIntent = await stripe.paymentIntents.create({
          amount: Math.round(Number(price) * 100),
          currency: 'usd',
          payment_method_types: ['card'],
        });
        res.send({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        res.status(500).send({ message: 'Stripe error', error: error.message });
      }
    });

    app.post('/payments/confirm', verifyJWT, async (req, res) => {
      try {
        const {
          bookingId,
          transactionId,
          ticketId,
          finalPrice,
          ticketTitle,
          userEmail,
          quantity,
        } = req.body;

        if (ticketId) {
          const ticketQuery = ObjectId.isValid(ticketId)
            ? { _id: new ObjectId(ticketId) }
            : { id: Number(ticketId) };
          const ticket = await ticketsCollection.findOne(ticketQuery);
          if (ticket && isDeparturePassed(ticket.date, ticket.time)) {
            return res
              .status(400)
              .send({ message: 'Cannot pay — departure time has passed.' });
          }
        }

        await transactionsCollection.insertOne({
          transactionId,
          amount: Number(finalPrice),
          ticketTitle: ticketTitle || 'Premium Transit Pass',
          userEmail,
          createdAt: new Date(),
        });

        await bookingsCollection.updateOne(
          { _id: new ObjectId(bookingId) },
          { $set: { status: 'paid' } },
        );

        if (ticketId) {
          const ticketQuery = ObjectId.isValid(ticketId)
            ? { _id: new ObjectId(ticketId) }
            : { id: Number(ticketId) };
          await ticketsCollection.updateOne(ticketQuery, {
            $inc: { seats: -Math.abs(Number(quantity || 1)) },
          });
        }

        res.send({ success: true, message: 'Payment captured securely.' });
      } catch (error) {
        res.status(500).send({ message: 'Payment processing failed', error });
      }
    });

    // ══════════════════════════════════════════
    // REVENUE STATS
    // ══════════════════════════════════════════

    app.get('/revenue/stats', verifyJWT, verifyVendor, async (req, res) => {
      try {
        const email = req.decoded.email;
        const myTickets = await ticketsCollection
          .find({ vendorEmail: email })
          .toArray();

        const ticketIds = myTickets.map(t => t._id.toString());
        const paidBookings = await bookingsCollection
          .find({ ticketId: { $in: ticketIds }, status: 'paid' })
          .toArray();

        const totalRevenue = paidBookings.reduce(
          (sum, b) => sum + (Number(b.price) || 0),
          0,
        );
        const totalSold = paidBookings.reduce(
          (sum, b) => sum + (Number(b.quantity) || 0),
          0,
        );

        const byType = ['Bus', 'Train', 'Plane', 'Launch'].map(type => {
          const typeTickets = myTickets.filter(t => t.type === type);
          const typeIds = typeTickets.map(t => t._id.toString());
          const typeBookings = paidBookings.filter(b =>
            typeIds.includes(b.ticketId),
          );
          const typeRevenue = typeBookings.reduce(
            (sum, b) => sum + (Number(b.price) || 0),
            0,
          );
          return {
            name: type,
            tickets: typeTickets.length,
            revenue: typeRevenue,
            sold: typeBookings.reduce(
              (sum, b) => sum + (Number(b.quantity) || 0),
              0,
            ),
          };
        });

        res.send({
          totalTickets: myTickets.length,
          totalSold,
          totalRevenue,
          byType,
        });
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error fetching revenue stats', error });
      }
    });

    // ══════════════════════════════════════════
    // USER MANAGEMENT
    // ══════════════════════════════════════════

    app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const result = await usersCollection
          .find({}, { projection: { password: 0 } })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error fetching users', error });
      }
    });

    app.patch('/users/role/:id', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const { role } = req.body;
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { role } },
        );
        res.send({ success: true, result });
      } catch (error) {
        res.status(500).send({ message: 'Error updating role', error });
      }
    });

    app.patch('/users/fraud/:id', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const vendor = await usersCollection.findOne({
          _id: new ObjectId(req.params.id),
        });
        if (!vendor)
          return res.status(404).send({ message: 'User not found.' });

        await usersCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { isFraud: true } },
        );
        await ticketsCollection.updateMany(
          { vendorEmail: vendor.email },
          { $set: { isHidden: true } },
        );
        res.send({
          success: true,
          message: 'Vendor flagged and tickets hidden.',
        });
      } catch (error) {
        res.status(500).send({ message: 'Error flagging fraud', error });
      }
    });

    app.get('/transactions', verifyJWT, async (req, res) => {
      try {
        const { email } = req.query;
        const queryEmail =
          req.decoded.role === 'admin' ? email : req.decoded.email;
        const query = queryEmail ? { userEmail: queryEmail } : {};
        const result = await transactionsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error fetching transactions', error });
      }
    });
  } finally {
    // keep alive
  }
}

run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('🚀 TicketBari Server running!');
});

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
