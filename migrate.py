import psycopg2

conn = psycopg2.connect(
    host="watchgraph-db.cfsm0oa8qcbn.us-east-2.rds.amazonaws.com",
    port=5432,
    dbname="postgres",
    user="postgres",
    password="IntelliSense2024"
)

cur = conn.cursor()

migrations = [
    "ALTER TABLE ai_systems ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);",
    "ALTER TABLE compliance_requirements ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);",
    "ALTER TABLE compliance_events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);"
]

for sql in migrations:
    try:
        cur.execute(sql)
        print(f"Done: {sql}")
    except Exception as e:
        print(f"Error: {sql}: {e}")

conn.commit()
cur.close()
conn.close()
print("Migration complete!")