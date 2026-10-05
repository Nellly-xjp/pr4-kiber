const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs/promises');
const path = require('path');

const app = express();
const PORT = 3000;
const USERS_FILE = path.join(__dirname, 'users.json');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'super_secret_key_change_in_production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 }
}));

app.use(express.static(path.join(__dirname, 'public')));

async function getUsers() {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    return [];
  }
}

async function saveUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
}

// Middlewares для захисту
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({ message: 'Неавторизований доступ. Увійдіть у систему.' });
}

// Додаткове завдання 11: сторінка 403
function isAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'ADMIN') {
    return next();
  }
  return res.status(403).sendFile(path.join(__dirname, 'public', '403.html'));
}

// --- МАРШРУТИ АУТЕНТИФІКАЦІЇ ---

app.post('/api/register', async (req, res) => {
  let { username, password } = req.body;

  // Додаткове завдання 9: Заборона username з пробілів
  const cleanUsername = username ? username.trim() : '';
  if (!cleanUsername) {
    return res.status(400).json({ message: 'Ім\'я користувача не може бути порожнім або складатися лише з пробілів.' });
  }

  // Додаткове завдання 8: Перевірка мінімальної довжини пароля (>= 8 символів)
  if (!password || password.length < 8) {
    return res.status(400).json({ message: 'Пароль повинен містити щонайменше 8 символів.' });
  }

  const users = await getUsers();

  // Додаткове завдання 10: Повідомлення при повторній реєстрації
  const existingUser = users.find(u => u.username.toLowerCase() === cleanUsername.toLowerCase());
  if (existingUser) {
    return res.status(400).json({ message: 'Користувач з таким іменем вже існує!' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: Date.now(),
    username: cleanUsername,
    password: hashedPassword,
    role: 'USER',
    lastLogin: null // Додаткове завдання 12
  };

  users.push(newUser);
  await saveUsers(users);

  res.status(201).json({ message: 'Користувача успішно зареєстровано!' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  const users = await getUsers();
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(400).json({ message: 'Невірне ім\'я користувача або пароль.' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Невірне ім\'я користувача або пароль.' });
  }

  // Додаткове завдання 12: Оновлення часу останнього успішного входу
  const loginTime = new Date().toLocaleString('uk-UA');
  user.lastLogin = loginTime;
  await saveUsers(users);

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role,
    lastLogin: user.lastLogin
  };

  res.json({ message: 'Вхід успішний!', user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: 'Помилка виходу.' });
    res.clearCookie('connect.sid');
    res.json({ message: 'Успішний вихід.' });
  });
});

app.get('/api/me', isAuthenticated, async (req, res) => {
  // Завантажуємо свіжі дані з JSON
  const users = await getUsers();
  const currentUser = users.find(u => u.id === req.session.user.id);
  if (currentUser) {
    req.session.user.lastLogin = currentUser.lastLogin;
  }
  res.json({ user: req.session.user });
});

// Додаткове завдання 14: Список користувачів тільки для ADMIN
app.get('/api/users', isAuthenticated, isAdmin, async (req, res) => {
  const users = await getUsers();
  const safeUsers = users.map(u => ({ id: u.id, username: u.username, role: u.role, lastLogin: u.lastLogin }));
  res.json({ users: safeUsers });
});

// --- ЗАХИЩЕНІ СТОРІНКИ ---

app.get('/home', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/profile', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.listen(PORT, () => console.log(`Сервер працює на http://localhost:${PORT}`));