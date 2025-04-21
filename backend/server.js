// Added user authentication with JWT and bcrypt
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Enable CORS for frontend origin
app.use(cors({
  origin: 'http://localhost:3000' // Adjust this to your frontend URL
}));

// Middleware to parse JSON bodies
app.use(express.json());

// In-memory user store (for demo purposes)
const users = [];

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token manquant' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token invalide' });
    req.user = user;
    next();
  });
}

// Root route to confirm server is running
app.get('/', (req, res) => {
  res.send('Koha backend server with auth is running');
});

// User registration route
app.post('/register', async (req, res) => {
  const { username, email, password, contact } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ message: 'Tous les champs requis sauf contact doivent être remplis' });
  }
  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(409).json({ message: 'Email déjà utilisé' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: users.length + 1, username, email, password: hashedPassword, contact: contact || '' };
    users.push(newUser);
    res.status(201).json({ message: 'Utilisateur enregistré avec succès' });
  } catch (error) {
    res.status(500).json({ message: 'Erreur interne' });
  }
});

// User login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(404).json({ message: 'Utilisateur non trouvé' });
  }
  try {
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'Mot de passe incorrect' });
    }
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Erreur interne' });
  }
});

// Protected route to get list of books from Koha
app.get('/api/books', authenticateToken, async (req, res) => {
  try {
    const response = await axios.get(`${process.env.KOHA_API_BASE_URL}/books`, {
      headers: {
        'Authorization': `Bearer ${process.env.KOHA_API_KEY}`
      }
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching books from Koha:', error.message);
    res.status(500).json({ error: 'Failed to fetch books from Koha' });
  }
});

// Protected route to get book details by id
app.get('/api/books/:id', authenticateToken, async (req, res) => {
  const bookId = req.params.id;
  try {
    const response = await axios.get(`${process.env.KOHA_API_BASE_URL}/books/${bookId}`, {
      headers: {
        'Authorization': `Bearer ${process.env.KOHA_API_KEY}`
      }
    });
    res.json(response.data);
  } catch (error) {
    console.error(`Error fetching book ${bookId} from Koha:`, error.message);
    res.status(500).json({ error: 'Failed to fetch book details from Koha' });
  }
});

// Protected route to reserve a book (checkout) via Koha API
app.post('/api/reserve', authenticateToken, async (req, res) => {
  const { item_id, borrower_id } = req.body;
  if (!item_id || !borrower_id) {
    return res.status(400).json({ success: false, message: 'item_id and borrower_id are required' });
  }
  try {
    const response = await axios.post(`${process.env.KOHA_API_BASE_URL}/checkout`, {
      item_id,
      borrower_id
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.KOHA_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    if (response.data && response.data.success) {
      res.json({ success: true });
    } else {
      res.json({ success: false, message: response.data.message || 'Reservation failed' });
    }
  } catch (error) {
    console.error('Error reserving book via Koha:', error.message);
    res.status(500).json({ success: false, message: 'Failed to reserve book' });
  }
});

// New route for /api/v1/biblios to fetch books (same as /api/books)
app.get('/api/v1/biblios', authenticateToken, async (req, res) => {
  try {
    const response = await axios.get(`${process.env.KOHA_API_BASE_URL}/books`, {
      headers: {
        'Authorization': `Bearer ${process.env.KOHA_API_KEY}`
      }
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching books from Koha:', error.message);
    res.status(500).json({ error: 'Failed to fetch books from Koha' });
  }
});

// New route for /api/v1/holds to place a hold/reservation (same as /api/reserve)
app.post('/api/v1/holds', authenticateToken, async (req, res) => {
  const { item_id, borrower_id } = req.body;
  if (!item_id || !borrower_id) {
    return res.status(400).json({ success: false, message: 'item_id and borrower_id are required' });
  }
  try {
    const response = await axios.post(`${process.env.KOHA_API_BASE_URL}/checkout`, {
      item_id,
      borrower_id
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.KOHA_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    if (response.data && response.data.success) {
      res.json({ success: true });
    } else {
      res.json({ success: false, message: response.data.message || 'Reservation failed' });
    }
  } catch (error) {
    console.error('Error placing hold via Koha:', error.message);
    res.status(500).json({ success: false, message: 'Failed to place hold' });
  }
});

app.listen(port, () => {
  console.log(`Backend server listening at http://localhost:${port}`);
});
