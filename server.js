const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Database initialization
const db = new sqlite3.Database('./timetracking.db', (err) => {
  if (err) console.error('Database error:', err);
  else console.log('Connected to SQLite database');
});

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS managers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    manager_id INTEGER,
    name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(manager_id) REFERENCES managers(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS shifts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER,
    clock_in DATETIME,
    clock_out DATETIME,
    duration_hours REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(employee_id) REFERENCES employees(id) ON DELETE CASCADE
  )`);
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.managerId = decoded.id;
    next();
  });
};

// Register manager
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    'INSERT INTO managers (username, password) VALUES (?, ?)',
    [username, hashedPassword],
    function(err) {
      if (err) {
        return res.status(400).json({ error: 'Username already exists' });
      }
      res.json({ id: this.lastID, username });
    }
  );
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get('SELECT * FROM managers WHERE username = ?', [username], async (err, manager) => {
    if (err || !manager) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, manager.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: manager.id, username: manager.username }, JWT_SECRET, {
      expiresIn: '7d'
    });

    res.json({ token, manager: { id: manager.id, username: manager.username } });
  });
});

// Get all employees for manager
app.get('/api/employees', verifyToken, (req, res) => {
  db.all(
    'SELECT * FROM employees WHERE manager_id = ?',
    [req.managerId],
    (err, employees) => {
      if (err) return res.status(500).json({ error: err.message });
      
      // Get shifts for each employee
      const employeeData = employees.map(emp => {
        return new Promise((resolve) => {
          db.all(
            'SELECT * FROM shifts WHERE employee_id = ?',
            [emp.id],
            (err, shifts) => {
              resolve({
                ...emp,
                shifts: shifts || [],
                totalHours: (shifts || []).reduce((sum, s) => sum + (s.duration_hours || 0), 0)
              });
            }
          );
        });
      });

      Promise.all(employeeData).then(data => res.json(data));
    }
  );
});

// Add employee
app.post('/api/employees', verifyToken, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });

  db.run(
    'INSERT INTO employees (manager_id, name) VALUES (?, ?)',
    [req.managerId, name],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, manager_id: req.managerId, name });
    }
  );
});

// Delete employee
app.delete('/api/employees/:id', verifyToken, (req, res) => {
  db.run(
    'DELETE FROM employees WHERE id = ? AND manager_id = ?',
    [req.params.id, req.managerId],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Employee deleted' });
    }
  );
});

// Clock in
app.post('/api/clock-in', verifyToken, (req, res) => {
  const { employeeId } = req.body;
  if (!employeeId) return res.status(400).json({ error: 'Employee ID required' });

  const clockInTime = new Date().toISOString();

  db.run(
    'INSERT INTO shifts (employee_id, clock_in) VALUES (?, ?)',
    [employeeId, clockInTime],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, employeeId, clock_in: clockInTime });
    }
  );
});

// Clock out
app.post('/api/clock-out', verifyToken, (req, res) => {
  const { shiftId } = req.body;
  if (!shiftId) return res.status(400).json({ error: 'Shift ID required' });

  db.get('SELECT * FROM shifts WHERE id = ?', [shiftId], (err, shift) => {
    if (err || !shift) return res.status(404).json({ error: 'Shift not found' });

    const clockOutTime = new Date().toISOString();
    const clockIn = new Date(shift.clock_in);
    const clockOut = new Date(clockOutTime);
    const duration = (clockOut - clockIn) / (1000 * 60 * 60);

    db.run(
      'UPDATE shifts SET clock_out = ?, duration_hours = ? WHERE id = ?',
      [clockOutTime, duration, shiftId],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: shiftId, clock_out: clockOutTime, duration_hours: duration });
      }
    );
  });
});

// Get employee shifts
app.get('/api/employees/:id/shifts', verifyToken, (req, res) => {
  db.all(
    'SELECT * FROM shifts WHERE employee_id = ?',
    [req.params.id],
    (err, shifts) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(shifts);
    }
  );
});

// Export to CSV
app.get('/api/export/csv', verifyToken, (req, res) => {
  db.all(
    `SELECT e.name, s.clock_in, s.clock_out, s.duration_hours 
     FROM employees e 
     JOIN shifts s ON e.id = s.employee_id 
     WHERE e.manager_id = ?`,
    [req.managerId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });

      let csv = 'Name,Clock In,Clock Out,Duration (hours)\n';
      rows.forEach(row => {
        csv += `"${row.name}","${row.clock_in}","${row.clock_out}","${row.duration_hours}"\n`;
      });

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="timetracking.csv"');
      res.send(csv);
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});