# TicketBari — Server

Backend API for the TicketBari online ticket booking platform.

## Live API
https://ticket-bari-server.onrender.com

## Tech Stack
- Node.js + Express.js
- MongoDB Atlas
- JWT Authentication
- bcryptjs
- Stripe Payment
- CORS

## NPM Packages
- express
- mongodb
- jsonwebtoken
- bcryptjs
- stripe
- cors
- dotenv

## API Endpoints

### Auth
- POST /register
- POST /login
- POST /auth/social-sync

### Tickets
- GET /tickets
- GET /tickets/:id
- GET /tickets/advertised
- GET /tickets/latest
- POST /tickets
- PATCH /tickets/:id
- DELETE /tickets/:id

### Bookings
- GET /bookings
- POST /bookings
- PATCH /bookings/:id/status
- DELETE /bookings/:id

### Payments
- POST /create-checkout-session
- POST /payments/confirm

### Admin
- GET /users
- PATCH /users/role/:id
- PATCH /users/fraud/:id

## Environment Variables
```
PORT=5000
MONGODB_URI=
JWT_SECRET=
STRIPE_SECRET_KEY=
CLIENT_URL=
SEED_SECRET=
```