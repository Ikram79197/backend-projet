// server.js - Configuration de base
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: '*', // Autoriser toutes les origines
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Routes de base
app.get('/', (req, res) => {
 res.json({ message: 'API opérationnelle' });
});

// Démarrage du serveur
app.listen(PORT, () => {
 console.log(`Serveur en écoute sur le port ${PORT}`);
});

// Données mock pour l'exemple
let tasks = [
  { id: 1, title: 'Apprendre Express', completed: false },
  { id: 2, title: 'Créer une API REST', completed: false }
];

// Route pour récupérer toutes les tâches
app.get('/api/tasks', (req, res) => {
  res.json(tasks);
});

// Route pour récupérer une tâche spécifique
app.get('/api/tasks/:id', (req, res) => {
  const task = tasks.find(t => t.id === parseInt(req.params.id));
  if (!task) return res.status(404).json({ error: "Tâche non trouvée" });
  res.json(task);
});

// Route pour créer une nouvelle tâche
app.post('/api/tasks', (req, res) => {
  const newTask = {
    id: tasks.length + 1,
    title: req.body.title,
    completed: false
  };
  tasks.push(newTask);
  res.status(200).json(newTask);
});

// Route pour modifier une tâche existante
app.put('/api/tasks/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const taskIndex = tasks.findIndex(t => t.id === id);
  
  if (taskIndex === -1) {
    return res.status(404).json({ error: "Tâche non trouvée" });
  }
  
  const updatedTask = {
    id: id,
    title: req.body.title || tasks[taskIndex].title,
    completed: req.body.completed !== undefined ? req.body.completed : tasks[taskIndex].completed
  };
  
  tasks[taskIndex] = updatedTask;
  res.json(updatedTask);
});

// Route pour supprimer une tâche
app.delete('/api/tasks/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const taskIndex = tasks.findIndex(t => t.id === id);
  
  if (taskIndex === -1) {
    return res.status(404).json({ error: "Tâche non trouvée" });
  }
  
  const deletedTask = tasks[taskIndex];
  tasks.splice(taskIndex, 1);
  
  res.json({ message: "Tâche supprimée avec succès", deletedTask });
});