import dotenv from 'dotenv';
dotenv.config();

import { app } from './app.js';
import { runMigrations } from './db/migrate.js';
import { seedDatabase } from './db/seed.js';

const PORT = process.env.PORT || 3000;

async function initializeDatabaseWithRetry(maxRetries = 10, delayMs = 2000) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`Database initialization attempt ${attempt}/${maxRetries}...`);
      await runMigrations();
      await seedDatabase();
      console.log('Database initialized and seeded successfully.');
      return;
    } catch (err) {
      console.warn(`Database connection attempt ${attempt} failed: ${err.message}`);
      if (attempt === maxRetries) {
        console.error('Max database connection retries reached. Exiting.');
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}

async function startServer() {
  try {
    await initializeDatabaseWithRetry();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Authentication server is running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();
