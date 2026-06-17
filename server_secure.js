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
  db.run(`CREATE TABLE IF NOT EXISTS manager (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

  // Check if manager exists, if not create placeholder
  db.get('SELECT COUNT(*) as count FROM manager', (err, row) => {
    if (row && row.count === 0) {
      // No manager exists yet - one will be created on first registration
      console.log('No manager account exists. Create one on first registration.');
    }
  });
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.managerId = decoded.id;
    req.username = decoded.username;
    next();
  });
};

// REGISTER MANAGER (Only one time!)
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  // Check if manager already exists
  db.get('SELECT COUNT(*) as count FROM manager', async (err, row) => {
    if (row && row.count > 0) {
      return res.status(403).json({ error: 'Manager account already exists. Use login instead.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO manager (username, password) VALUES (?, ?)',
      [username, hashedPassword],
      function(err) {
        if (err) {
          return res.status(400).json({ error: 'Error creating manager account' });
        }
        res.json({ id: this.lastID, username, message: 'Manager account created successfully!' });
      }
    );
  });
});

// LOGIN MANAGER
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get('SELECT * FROM manager WHERE username = ?', [username], async (err, manager) => {
    if (err || !manager) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, manager.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: manager.id, username: manager.username, role: 'manager' }, JWT_SECRET, {
      expiresIn: '7d'
    });

    res.json({ 
      token, 
      role: 'manager',
      manager: { id: manager.id, username: manager.username } 
    });
  });
});

// GET ALL EMPLOYEES (for dropdown)
app.get('/api/employees', (req, res) => {
  db.all('SELECT id, name FROM employees ORDER BY name', (err, employees) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(employees || []);
  });
});

// GET EMPLOYEES WITH DETAILS (MANAGER ONLY)
app.get('/api/employees/details/all', verifyToken, (req, res) => {
  db.all(
    'SELECT * FROM employees ORDER BY name',
    (err, employees) => {
      if (err) return res.status(500).json({ error: err.message });
      
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

// ADD EMPLOYEE (MANAGER ONLY)
app.post('/api/employees', verifyToken, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });

  db.run(
    'INSERT INTO employees (name) VALUES (?)',
    [name],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, name });
    }
  );
});

// DELETE EMPLOYEE (MANAGER ONLY)
app.delete('/api/employees/:id', verifyToken, (req, res) => {
  db.run(
    'DELETE FROM employees WHERE id = ?',
    [req.params.id],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Employee deleted' });
    }
  );
});

// CLOCK IN (WORKER - NO AUTH REQUIRED)
app.post('/api/clock-in', (req, res) => {
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

// CLOCK OUT (WORKER - NO AUTH REQUIRED)
app.post('/api/clock-out', (req, res) => {
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

// GET EMPLOYEE SHIFTS
app.get('/api/employees/:id/shifts', (req, res) => {
  db.all(
    'SELECT * FROM shifts WHERE employee_id = ?',
    [req.params.id],
    (err, shifts) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(shifts);
    }
  );
});

// EXPORT TO CSV (MANAGER ONLY)
app.get('/api/export/csv', verifyToken, (req, res) => {
  db.all(
    `SELECT e.name, s.clock_in, s.clock_out, s.duration_hours 
     FROM employees e 
     JOIN shifts s ON e.id = s.employee_id 
     ORDER BY e.name, s.clock_in`,
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

// CHECK IF MANAGER EXISTS
app.get('/api/manager/exists', (req, res) => {
  db.get('SELECT COUNT(*) as count FROM manager', (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ exists: row.count > 0 });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});