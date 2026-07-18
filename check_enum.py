import psycopg2
conn = psycopg2.connect(
    host="watchgraph-db.cfsm0oa8qcbn.us-east-2.rds.amazonaws.com",
    port=5432,
    dbname="postgres",
    user="postgres",
    password="IntelliSense2024"
)
cur = conn.cursor()
cur.execute("SELECT enumlabel FROM pg_enum WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'compliancestatus')")
print("Compliance status enum values:", [row[0] for row in cur.fetchall()])
cur.close()
conn.close()