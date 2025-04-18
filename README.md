# Express-API-with-React-client
## Todo API Server

### Description
This is a full-stack application for managing tasks. It consists of a Node.js/Express backend API and a React frontend client.

### Features
- View all tasks
- Create new tasks
- Edit existing tasks
- Mark tasks as completed/incomplete
- Delete tasks

### Tech Stack
- Backend: Node.js, Express.js
- Frontend: React.js
- API Client: Axios
- Styling: CSS Modules

### Project Structure
api-server/ 

├── client/ # React frontend 

│ ├── src/ │ 

│ ├── components/ # React components 

│ │ ├── services/ # API services 

│ │ └── App.css # Global styles 

│ └── package.json 

├── server.js # Express server 

└── package.json

### Getting Started

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Yassercom/todo-api-server.git
cd todo-api-server
1. Clone the repository:
```
2. Install backend dependencies:
 ```bash
npm install
```

Install frontend dependencies:
 ```bash
cd client
npm install
cd ..
```

### Running the Application

1. Start the backend server:
 ```bash
node server.js
```

2. Start the frontend development server:
 ```bash
cd client
npm start
```

The application will be available at:

Frontend: http://localhost:3000
API: http://localhost:5000

## API Endpoints
### Tasks
. GET /api/tasks - Get all tasks .

. GET /api/tasks/:id - Get a specific task .

. POST /api/tasks - Create a new task .

. PUT /api/tasks/:id - Update a task .

. DELETE /api/tasks/:id - Delete a task .

### Contributing
1. Fork the repository .
2. Create a feature branch .
3. Commit your changes .
4. Push to the branch .
5. Create a Pull Request .


