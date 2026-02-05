const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

async function migrate() {
    const sql = fs.readFileSync(
        path.join(__dirname, '../src/database/migrations/001_auth_schema.sql'),
        'utf8'
    );

    await pool.query(sql);
    console.log('✅ Migration completed');
    await pool.end();
}

migrate().catch(console.error);