How to Run Locally 
Clone this repository.

Navigate to the project directory.

Install dependencies using npm install.

Create a database with pgAdmin and tables 'users' and 'todolist' with appropriate columns:

users:

id (primary key) username, email, password

todlist:

id (primary key) title, user_id

Create a .env file in your project directory with your database connection details:

DB_USER="your_username" DB_HOST="your_host_address" DB_DATABASE="your_database_name" DB_PASSWORD="your_password" DB_PORT="your_database_port"

Start the server using nodemon app.js.

Access the website in your browser at http://localhost:3000.
