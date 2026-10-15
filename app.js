
// GET API: Create the users table
// 
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { pool, createTables } = require("./db");

const app = express();
const PORT = 5000;

// Middleware
app.use(express.json());

// Keep this same secret for signing and verifying tokens.
// For a real application, use a secure secret outside your source code.
const JWT_SECRET = "my_task_management_secret_change_this";

// -------------------- AUTHENTICATION MIDDLEWARE --------------------

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Please provide a valid Bearer token.",
    });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        message: "Invalid or expired token.",
      });
    }

    req.user = user;
    next();
  });
}

// -------------------- HELPER FUNCTIONS --------------------

function isPositiveInteger(value) {
  return Number.isInteger(Number(value)) && Number(value) > 0;
}

function handleDatabaseError(res, error) {
  console.error(error);

  if (error.code === "23505") {
    return res.status(409).json({
      message: "This record already exists.",
    });
  }

  if (error.code === "23503") {
    return res.status(400).json({
      message: "Related record does not exist or is still in use.",
    });
  }

  return res.status(500).json({
    message: "Internal server error.",
  });
}

// -------------------- HOME ROUTE --------------------

app.get("/", (req, res) => {
  res.json({
    message: "Task Management API is running.",
  });
});

// ================================================================
//                         USER ROUTES
// ================================================================

// Register a new user
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== "string" ||
      !name.trim() ||
      typeof email !== "string" ||
      !email.trim() ||
      typeof password !== "string" ||
      password.length < 6
    ) {
      return res.status(400).json({
        message: "Name, valid email, and password of at least 6 characters are required.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        message: "Email is already registered.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (name, email, password)
       VALUES ($1, $2, $3)
       RETURNING id, name, email`,
      [name.trim(), normalizedEmail, hashedPassword]
    );

    return res.status(201).json({
      message: "User registered successfully.",
      user: result.rows[0],
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    const result = await pool.query(
      "SELECT id, name, email, password FROM users WHERE email = $1",
      [email.trim().toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const user = result.rows[0];
    const passwordMatches = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatches) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    return res.json({
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Get all users (requires login; returns no passwords)
app.get("/users", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, email, created_at FROM users ORDER BY id"
    );

    return res.json(result.rows);
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Get your own user profile
app.get("/users/:id", authenticateToken, async (req, res) => {
  try {
    if (!isPositiveInteger(req.params.id)) {
      return res.status(400).json({ message: "Invalid user ID." });
    }

    if (Number(req.params.id) !== req.user.id) {
      return res.status(403).json({
        message: "You can only view your own profile.",
      });
    }

    const result = await pool.query(
      "SELECT id, name, email, created_at FROM users WHERE id = $1",
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Update your own profile
app.patch("/users/:id", authenticateToken, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const userId = Number(req.params.id);

    if (!isPositiveInteger(userId)) {
      return res.status(400).json({ message: "Invalid user ID." });
    }

    if (userId !== req.user.id) {
      return res.status(403).json({
        message: "You can only update your own profile.",
      });
    }

    if (name === undefined && email === undefined && password === undefined) {
      return res.status(400).json({
        message: "Provide name, email, or password to update.",
      });
    }

    if (name !== undefined && (typeof name !== "string" || !name.trim())) {
      return res.status(400).json({ message: "Name cannot be empty." });
    }

    if (
      email !== undefined &&
      (typeof email !== "string" || !email.trim())
    ) {
      return res.status(400).json({ message: "Email cannot be empty." });
    }

    if (
      password !== undefined &&
      (typeof password !== "string" || password.length < 6)
    ) {
      return res.status(400).json({
        message: "Password must contain at least 6 characters.",
      });
    }

    const current = await pool.query(
      "SELECT name, email, password FROM users WHERE id = $1",
      [userId]
    );

    if (current.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const oldUser = current.rows[0];
    const newName = name === undefined ? oldUser.name : name.trim();
    const newEmail =
      email === undefined ? oldUser.email : email.trim().toLowerCase();
    const newPassword =
      password === undefined
        ? oldUser.password
        : await bcrypt.hash(password, 10);

    const result = await pool.query(
      `UPDATE users
       SET name = $1, email = $2, password = $3
       WHERE id = $4
       RETURNING id, name, email, created_at`,
      [newName, newEmail, newPassword, userId]
    );

    return res.json({
      message: "User updated successfully.",
      user: result.rows[0],
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Delete your own account
app.delete("/users/:id", authenticateToken, async (req, res) => {
  try {
    const userId = Number(req.params.id);

    if (!isPositiveInteger(userId)) {
      return res.status(400).json({ message: "Invalid user ID." });
    }

    if (userId !== req.user.id) {
      return res.status(403).json({
        message: "You can only delete your own account.",
      });
    }

    const result = await pool.query(
      "DELETE FROM users WHERE id = $1 RETURNING id",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    return res.json({ message: "User deleted successfully." });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// ================================================================
//                        PROJECT ROUTES
// ================================================================

// Create a project
app.post("/projects", authenticateToken, async (req, res) => {
  try {
    const { name, description } = req.body;

    if (typeof name !== "string" || !name.trim()) {
      return res.status(400).json({
        message: "Project name is required.",
      });
    }

    const result = await pool.query(
      `INSERT INTO projects (name, description, owner_id)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [
        name.trim(),
        typeof description === "string" ? description.trim() : null,
        req.user.id,
      ]
    );

    return res.status(201).json({
      message: "Project created successfully.",
      project: result.rows[0],
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Get your projects, including task counts (JOIN)
app.get("/projects", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         p.id,
         p.name,
         p.description,
         p.owner_id,
         p.created_at,
         COUNT(t.id)::int AS total_tasks
       FROM projects p
       LEFT JOIN tasks t ON t.project_id = p.id
       WHERE p.owner_id = $1
       GROUP BY p.id
       ORDER BY p.id DESC`,
      [req.user.id]
    );

    return res.json(result.rows);
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Get one project
app.get("/projects/:id", authenticateToken, async (req, res) => {
  try {
    if (!isPositiveInteger(req.params.id)) {
      return res.status(400).json({ message: "Invalid project ID." });
    }

    const result = await pool.query(
      `SELECT p.id, p.name, p.description, p.owner_id, p.created_at,
              COUNT(t.id)::int AS total_tasks
       FROM projects p
       LEFT JOIN tasks t ON t.project_id = p.id
       WHERE p.id = $1 AND p.owner_id = $2
       GROUP BY p.id`,
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Project not found." });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Update a project
app.patch("/projects/:id", authenticateToken, async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!isPositiveInteger(req.params.id)) {
      return res.status(400).json({ message: "Invalid project ID." });
    }

    if (name === undefined && description === undefined) {
      return res.status(400).json({
        message: "Provide a name or description to update.",
      });
    }

    if (name !== undefined && (typeof name !== "string" || !name.trim())) {
      return res.status(400).json({ message: "Project name cannot be empty." });
    }

    if (
      description !== undefined &&
      description !== null &&
      typeof description !== "string"
    ) {
      return res.status(400).json({
        message: "Description must be text or null.",
      });
    }

    const result = await pool.query(
      `UPDATE projects
       SET name = CASE WHEN $1::boolean THEN $2 ELSE name END,
           description = CASE WHEN $3::boolean THEN $4 ELSE description END
       WHERE id = $5 AND owner_id = $6
       RETURNING *`,
      [
        name !== undefined,
        name === undefined ? null : name.trim(),
        description !== undefined,
        description === undefined
          ? null
          : description === null
            ? null
            : description.trim(),
        req.params.id,
        req.user.id,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Project not found." });
    }

    return res.json({
      message: "Project updated successfully.",
      project: result.rows[0],
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Delete a project
app.delete("/projects/:id", authenticateToken, async (req, res) => {
  try {
    if (!isPositiveInteger(req.params.id)) {
      return res.status(400).json({ message: "Invalid project ID." });
    }

    const result = await pool.query(
      `DELETE FROM projects
       WHERE id = $1 AND owner_id = $2
       RETURNING id`,
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Project not found." });
    }

    return res.json({ message: "Project deleted successfully." });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// ================================================================
//                          TASK ROUTES
// ================================================================

// Create a task
app.post("/tasks", authenticateToken, async (req, res) => {
  try {
    const {
      title,
      description,
      project_id,
      assigned_to,
      status,
      due_date,
    } = req.body;

    if (
      typeof title !== "string" ||
      !title.trim() ||
      !isPositiveInteger(project_id)
    ) {
      return res.status(400).json({
        message: "Task title and a valid project_id are required.",
      });
    }

    const allowedStatuses = ["pending", "in_progress", "completed"];
    const taskStatus = status === undefined ? "pending" : status;

    if (!allowedStatuses.includes(taskStatus)) {
      return res.status(400).json({
        message: "Status must be pending, in_progress, or completed.",
      });
    }

    if (
      assigned_to !== undefined &&
      assigned_to !== null &&
      !isPositiveInteger(assigned_to)
    ) {
      return res.status(400).json({ message: "Invalid assigned_to user ID." });
    }

    if (
      description !== undefined &&
      description !== null &&
      typeof description !== "string"
    ) {
      return res.status(400).json({ message: "Description must be text." });
    }

    if (
      due_date !== undefined &&
      due_date !== null &&
      (typeof due_date !== "string" ||
        Number.isNaN(Date.parse(due_date)))
    ) {
      return res.status(400).json({ message: "Invalid due_date." });
    }

    const project = await pool.query(
      "SELECT id FROM projects WHERE id = $1 AND owner_id = $2",
      [project_id, req.user.id]
    );

    if (project.rows.length === 0) {
      return res.status(404).json({
        message: "Project not found or you do not own it.",
      });
    }

    if (assigned_to !== undefined && assigned_to !== null) {
      const user = await pool.query(
        "SELECT id FROM users WHERE id = $1",
        [assigned_to]
      );

      if (user.rows.length === 0) {
        return res.status(400).json({
          message: "Assigned user does not exist.",
        });
      }
    }

    const result = await pool.query(
      `INSERT INTO tasks
         (title, description, project_id, assigned_to, status, due_date)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        title.trim(),
        description ?? null,
        project_id,
        assigned_to ?? null,
        taskStatus,
        due_date ?? null,
      ]
    );

    return res.status(201).json({
      message: "Task created successfully.",
      task: result.rows[0],
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Get tasks with JOIN, search, filtering, sorting, pagination and overdue filter
app.get("/tasks", authenticateToken, async (req, res) => {
  try {
    const {
      search,
      status,
      project_id,
      assigned_to,
      overdue,
      sortBy = "created_at",
      order = "DESC",
      page = "1",
      limit = "10",
    } = req.query;

    const allowedStatuses = ["pending", "in_progress", "completed"];
    const allowedSortColumns = ["created_at", "due_date", "title", "status"];
    const allowedOrders = ["ASC", "DESC"];

    if (status && !allowedStatuses.includes(status)) {
      return res.status(400).json({ message: "Invalid task status." });
    }

    if (project_id && !isPositiveInteger(project_id)) {
      return res.status(400).json({ message: "Invalid project_id." });
    }

    if (assigned_to && !isPositiveInteger(assigned_to)) {
      return res.status(400).json({ message: "Invalid assigned_to." });
    }

    if (!allowedSortColumns.includes(sortBy)) {
      return res.status(400).json({
        message: "sortBy must be created_at, due_date, title, or status.",
      });
    }

    const normalizedOrder = String(order).toUpperCase();

    if (!allowedOrders.includes(normalizedOrder)) {
      return res.status(400).json({ message: "order must be ASC or DESC." });
    }

    if (!/^\d+$/.test(String(page)) || Number(page) < 1) {
      return res.status(400).json({ message: "page must be at least 1." });
    }

    if (!/^\d+$/.test(String(limit)) || Number(limit) < 1 || Number(limit) > 100) {
      return res.status(400).json({
        message: "limit must be between 1 and 100.",
      });
    }

    if (overdue !== undefined && !["true", "false"].includes(overdue)) {
      return res.status(400).json({
        message: "overdue must be true or false.",
      });
    }

    const conditions = ["p.owner_id = $1"];
    const values = [req.user.id];

    function addCondition(sql, value) {
      values.push(value);
      conditions.push(sql.replace("?", `$${values.length}`));
    }

    if (search) {
      addCondition(
        "(t.title ILIKE ? OR COALESCE(t.description, '') ILIKE ?)",
        `%${search}%`
      );
      // The previous condition has two placeholders; replace it with
      // a safely parameterized pair.
      conditions.pop();
      values.pop();
      values.push(`%${search}%`, `%${search}%`);
      conditions.push(
        `(t.title ILIKE $${values.length - 1} OR COALESCE(t.description, '') ILIKE $${values.length})`
      );
    }

    if (status) {
      addCondition("t.status = ?", status);
    }

    if (project_id) {
      addCondition("t.project_id = ?", Number(project_id));
    }

    if (assigned_to) {
      addCondition("t.assigned_to = ?", Number(assigned_to));
    }

    if (overdue === "true") {
      conditions.push(
        "t.due_date < CURRENT_DATE AND t.status <> 'completed'"
      );
    } else if (overdue === "false") {
      conditions.push(
        "(t.due_date IS NULL OR t.due_date >= CURRENT_DATE OR t.status = 'completed')"
      );
    }

    const whereClause = conditions.join(" AND ");
    const offset = (Number(page) - 1) * Number(limit);

    const countResult = await pool.query(
      `SELECT COUNT(*)::int AS total
       FROM tasks t
       JOIN projects p ON p.id = t.project_id
       WHERE ${whereClause}`,
      values
    );

    const taskValues = [...values, Number(limit), offset];

    const result = await pool.query(
      `SELECT
         t.id,
         t.title,
         t.description,
         t.project_id,
         p.name AS project_name,
         t.assigned_to,
         u.name AS assigned_user_name,
         t.status,
         t.due_date,
         t.created_at,
         (t.due_date < CURRENT_DATE AND t.status <> 'completed') AS is_overdue
       FROM tasks t
       JOIN projects p ON p.id = t.project_id
       LEFT JOIN users u ON u.id = t.assigned_to
       WHERE ${whereClause}
       ORDER BY t.${sortBy} ${normalizedOrder} NULLS LAST
       LIMIT $${values.length + 1}
       OFFSET $${values.length + 2}`,
      taskValues
    );

    const total = countResult.rows[0].total;

    return res.json({
      page: Number(page),
      limit: Number(limit),
      total,
      totalPages: Math.ceil(total / Number(limit)),
      tasks: result.rows,
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Get one task
app.get("/tasks/:id", authenticateToken, async (req, res) => {
  try {
    if (!isPositiveInteger(req.params.id)) {
      return res.status(400).json({ message: "Invalid task ID." });
    }

    const result = await pool.query(
      `SELECT t.*, p.name AS project_name, u.name AS assigned_user_name,
              (t.due_date < CURRENT_DATE AND t.status <> 'completed') AS is_overdue
       FROM tasks t
       JOIN projects p ON p.id = t.project_id
       LEFT JOIN users u ON u.id = t.assigned_to
       WHERE t.id = $1 AND p.owner_id = $2`,
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Task not found." });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Update a task
app.patch("/tasks/:id", authenticateToken, async (req, res) => {
  try {
    const {
      title,
      description,
      project_id,
      assigned_to,
      status,
      due_date,
    } = req.body;

    if (!isPositiveInteger(req.params.id)) {
      return res.status(400).json({ message: "Invalid task ID." });
    }

    const hasUpdate = [
      title,
      description,
      project_id,
      assigned_to,
      status,
      due_date,
    ].some((value) => value !== undefined);

    if (!hasUpdate) {
      return res.status(400).json({
        message: "Provide at least one field to update.",
      });
    }

    if (title !== undefined && (typeof title !== "string" || !title.trim())) {
      return res.status(400).json({ message: "Title cannot be empty." });
    }

    if (
      description !== undefined &&
      description !== null &&
      typeof description !== "string"
    ) {
      return res.status(400).json({ message: "Description must be text or null." });
    }

    if (project_id !== undefined && !isPositiveInteger(project_id)) {
      return res.status(400).json({ message: "Invalid project_id." });
    }

    if (
      assigned_to !== undefined &&
      assigned_to !== null &&
      !isPositiveInteger(assigned_to)
    ) {
      return res.status(400).json({ message: "Invalid assigned_to." });
    }

    if (
      status !== undefined &&
      !["pending", "in_progress", "completed"].includes(status)
    ) {
      return res.status(400).json({ message: "Invalid task status." });
    }

    if (
      due_date !== undefined &&
      due_date !== null &&
      (typeof due_date !== "string" || Number.isNaN(Date.parse(due_date)))
    ) {
      return res.status(400).json({ message: "Invalid due_date." });
    }

    const current = await pool.query(
      `SELECT t.*
       FROM tasks t
       JOIN projects p ON p.id = t.project_id
       WHERE t.id = $1 AND p.owner_id = $2`,
      [req.params.id, req.user.id]
    );

    if (current.rows.length === 0) {
      return res.status(404).json({ message: "Task not found." });
    }

    const oldTask = current.rows[0];
    const newProjectId =
      project_id === undefined ? oldTask.project_id : Number(project_id);

    const project = await pool.query(
      "SELECT id FROM projects WHERE id = $1 AND owner_id = $2",
      [newProjectId, req.user.id]
    );

    if (project.rows.length === 0) {
      return res.status(400).json({
        message: "Project not found or you do not own it.",
      });
    }

    const newAssignedTo =
      assigned_to === undefined ? oldTask.assigned_to : assigned_to;

    if (newAssignedTo !== null) {
      const user = await pool.query(
        "SELECT id FROM users WHERE id = $1",
        [newAssignedTo]
      );

      if (user.rows.length === 0) {
        return res.status(400).json({
          message: "Assigned user does not exist.",
        });
      }
    }

    const result = await pool.query(
      `UPDATE tasks
       SET title = $1,
           description = $2,
           project_id = $3,
           assigned_to = $4,
           status = $5,
           due_date = $6
       WHERE id = $7
       RETURNING *`,
      [
        title === undefined ? oldTask.title : title.trim(),
        description === undefined ? oldTask.description : description,
        newProjectId,
        newAssignedTo,
        status === undefined ? oldTask.status : status,
        due_date === undefined ? oldTask.due_date : due_date,
        req.params.id,
      ]
    );

    return res.json({
      message: "Task updated successfully.",
      task: result.rows[0],
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// Delete a task
app.delete("/tasks/:id", authenticateToken, async (req, res) => {
  try {
    if (!isPositiveInteger(req.params.id)) {
      return res.status(400).json({ message: "Invalid task ID." });
    }

    const result = await pool.query(
      `DELETE FROM tasks t
       USING projects p
       WHERE t.project_id = p.id
         AND t.id = $1
         AND p.owner_id = $2
       RETURNING t.id`,
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Task not found." });
    }

    return res.json({ message: "Task deleted successfully." });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// ================================================================
//                         DASHBOARD ROUTE
// ================================================================

// Task statistics for the logged-in user
app.get("/dashboard", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         COUNT(t.id)::int AS total_tasks,
         COUNT(t.id) FILTER (WHERE t.status = 'completed')::int AS completed_tasks,
         COUNT(t.id) FILTER (WHERE t.status = 'pending')::int AS pending_tasks,
         COUNT(t.id) FILTER (WHERE t.status = 'in_progress')::int AS in_progress_tasks,
         COUNT(t.id) FILTER (
           WHERE t.due_date < CURRENT_DATE
             AND t.status <> 'completed'
         )::int AS overdue_tasks
       FROM projects p
       LEFT JOIN tasks t ON t.project_id = p.id
       WHERE p.owner_id = $1`,
      [req.user.id]
    );

    return res.json({
      message: "Dashboard statistics retrieved successfully.",
      statistics: result.rows[0],
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
});

// -------------------- NOT FOUND ROUTE --------------------

app.use((req, res) => {
  res.status(404).json({
    message: "Route not found.",
  });
});

// -------------------- START SERVER --------------------

async function startServer() {
  try {
    await pool.query("SELECT 1");
    await createTables();

    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}`);
      console.log("Database connected and tables are ready.");
    });
  } catch (error) {
    console.error("Could not start the server:", error.message);
    process.exit(1);
  }
}

startServer();

// Start the server

app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
