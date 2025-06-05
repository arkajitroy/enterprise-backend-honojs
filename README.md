To install dependencies:

```sh
bun install
```

To run:

```sh
bun run dev
```

open http://localhost:3000

---

Todo

- Create the REST APIs and other functionalities
- Add the controller and services (based on the classbased structure)

### Environment Variable

```bash
# APPLICATION CONFIGURATION
NODE_ENV=development
PORT=8000
HOST=localhost
CLIENT_URL=http://localhost:3000
API_VERSION=v1
API_PREFIX=/api

# MONGODB CONFIGURATION
MONGODB_LOCAL_URL=mongodb://localhost:27017
MONGODB_DB_NAME=hono_bun_api

# AUTHENTICATION CONFIGURATION
JWT_SECRET=2892cdc0a2d0c09f4605386dfa96a56eeab2e2eef08802efcff174781724f51f
REFRESH_TOKEN_SECRET=3ec4f2d0db896e832160c9ae25d4dbc47e3a4cf0d1a0c4a924c7c07612f95d69

```
