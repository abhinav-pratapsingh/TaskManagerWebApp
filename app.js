const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const methodOverride = require('method-override');
const path = require('path');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());
app.set('view engine', 'ejs');

mongoose.connect(process.env.db_url).then(console.log("success connection to db"));

const User = require('./models/User');
const Task = require('./models/Task');
const authenticateToken = require('./middlewares/auth');

app.get('/', (req, res) => res.redirect('/login'));

app.get('/signup', (req, res) => res.render('signup', { error: null }));
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.render('signup', { error: 'User already exists!' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  await User.create({ username, password: hashedPassword });
  res.redirect('/login');
});

app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.render('login', { error: 'Invalid credentials!' });
  }
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.cookie('token', token, { httpOnly: true });
  res.redirect('/tasks');
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.get('/tasks', authenticateToken, async (req, res) => {
  const tasks = await Task.find({ userId: req.user.id });
  res.render('tasks', { tasks });
});

app.post('/tasks', authenticateToken, async (req, res) => {
  const { title, completed } = req.body;
  await Task.create({ title, completed: completed === 'on', userId: req.user.id });
  res.redirect('/tasks');
});

app.get('/tasks/:id/edit', authenticateToken, async (req, res) => {
  const task = await Task.findById(req.params.id);
  res.render('editTask', { task });
});

app.put('/tasks/:id', authenticateToken, async (req, res) => {
  const { title, completed } = req.body;
  await Task.findByIdAndUpdate(req.params.id, {
    title,
    completed: completed === 'on',
  });
  res.redirect('/tasks');
});

app.delete('/tasks/:id', authenticateToken, async (req, res) => {
  await Task.findByIdAndDelete(req.params.id);
  res.redirect('/tasks');
});

app.listen(3000, () => console.log('Server started on http://localhost:3000'));
