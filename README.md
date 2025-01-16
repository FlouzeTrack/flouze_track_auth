# Pre-requisites

- Node.js version: 22 or higher
- Docker installed

# Setup

In order to run this project on your machine, you'll need all three repositories cloned and running. The following steps will guide you through the process for this repository:

- Clone this repository
- Run `npm install`
- You will need to create a .env file in the root directory with the following variables:

- Example .env file for flouze_track_auth

```
# ADONIS
TZ=UTC
PORT=4011
HOST=localhost
LOG_LEVEL=info
APP_KEY=
NODE_ENV=

DB_HOST=
DB_PORT=
DB_USER=
DB_PASSWORD=
DB_DATABASE=

# DATABSE
MYSQL_DATABASE=
MYSQL_PASSWORD=
MYSQL_ROOT_PASSWORD=

# REDIS
REDIS_HOST=
REDIS_PORT=
LIMITER_STORE=

# SMTP
SMTP_HOST=
SMTP_PORT=
SMTP_USERNAME=
SMTP_PASSWORD=
```

- Once the environment variables are set, you may run the following command in the root directory of this repository to start the docker containers:

```
docker-compose up --build
```

- The API is then available at http://localhost:4010/api/v1

# API Endpoints

## À COMPLÉTER

# Folder Structure

- This repository was built using the adonisjs framework. The folder structure is as follows:

```
app
├── Controllers
├── Services
├── Auth (Middleware for authentification)
├── Enums
├── Types
├── Models
├── Validators
├── Exceptions
├── Middleware
├── Commands
```

# Testing

- The tests are located in the test folder. They are written using the adonisjs testing framework.
- In order to run the tests, you may use the following command:

```
npm run test
```

# Security

## À COMPLÉTER
