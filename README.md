# nrgp-backend

Backend API for the NRGP Non-Returnable Gate Pass web app.

## Setup

1. Install dependencies:
   ```
   npm install
   ```
2. Create a `.env` file with:
   ```
   DATABASE_URL=postgres://...        # Neon connection string
   JWT_SECRET=<a long random secret>  # required — the server refuses to start without it
   PORT=5000
   CORS_ORIGIN=https://your-frontend-domain   # comma-separated list; omit to allow any origin
   ```
3. Create the schema on a fresh database:
   ```
   psql "$DATABASE_URL" -f schema.sql
   ```
4. Create the first admin account (never commit real credentials):
   ```
   ADMIN_EMAIL=admin@example.com ADMIN_NAME="Portal Admin" ADMIN_PASSWORD='choose-a-strong-password' npm run seed:admin
   ```
5. Start the server:
   ```
   npm start
   ```
