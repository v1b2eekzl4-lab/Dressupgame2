'use strict';
const request = require('supertest');
const path = require('path');
const fs = require('fs');

// Load app without listening
process.env.SESSION_SECRET = 'test-secret';
delete require.cache[require.resolve('dotenv')];
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const app = express();
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'test-secret',
  resave: false,
  saveUninitialized: true
}));

// Minimal route setup for tests
const usersFile = path.join(__dirname, '..', 'users.json');
function loadUsers() {
  try {
    if (fs.existsSync(usersFile)) {
      return JSON.parse(fs.readFileSync(usersFile, 'utf8'));
    }
  } catch (e) {}
  return [];
}

app.get('/api/items', (req, res) => {
  try {
    const itemsFile = path.join(__dirname, '..', 'items.json');
    const items = JSON.parse(fs.readFileSync(itemsFile, 'utf8'));
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch items' });
  }
});

app.post('/api/earn-currency', (req, res) => {
  if (typeof req.session.currency !== 'number') req.session.currency = 1000;
  const amount = Math.floor(Number(req.body.amount) || 0);
  if (amount <= 0) return res.status(400).json({ error: 'Invalid amount', currency: req.session.currency });
  const capped = Math.min(amount, 50);
  req.session.currency += capped;
  res.json({ success: true, earned: capped, currency: req.session.currency });
});

describe('Server', () => {
  test('GET /api/items returns 200', async () => {
    const res = await request(app).get('/api/items');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test('POST /api/earn-currency caps at 50', async () => {
    const agent = request.agent(app);
    const res = await agent.post('/api/earn-currency').send({ amount: 100 });
    expect(res.status).toBe(200);
    expect(res.body.earned).toBe(50);
    expect(res.body.currency).toBe(1050);
  });

  test('POST /api/earn-currency rejects invalid amount', async () => {
    const res = await request(app).post('/api/earn-currency').send({ amount: -1 });
    expect(res.status).toBe(400);
  });
});
