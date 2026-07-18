import psycopg2
import uuid
from datetime import datetime, timedelta

conn = psycopg2.connect(
    host="watchgraph-db.cfsm0oa8qcbn.us-east-2.rds.amazonaws.com",
    port=5432,
    dbname="postgres",
    user="postgres",
    password="IntelliSense2024"
)
cur = conn.cursor()

# Get existing framework IDs
cur.execute("SELECT id, short_code FROM frameworks")
frameworks = {row[1]: row[0] for row in cur.fetchall()}
print(f"Found frameworks: {list(frameworks.keys())}")

eu_ai_act_id = frameworks.get('eu-ai-act')
nist_id = frameworks.get('nist-ai-rmf')
iso_id = frameworks.get('iso-42001')

# ============================================
# 1. SEED COMPLIANCE REQUIREMENTS
# ============================================
requirements = [
    # EU AI Act requirements
    (str(uuid.uuid4()), "Article 9", "Risk Management System", "Establish and maintain a risk management system throughout the AI system lifecycle", '["HIGH", "UNACCEPTABLE"]'),
    (str(uuid.uuid4()), "Article 10", "Data Governance", "Training, validation and testing data shall be subject to appropriate data governance", '["HIGH"]'),
    (str(uuid.uuid4()), "Article 11", "Technical Documentation", "Technical documentation shall be drawn up before the AI system is placed on the market", '["HIGH"]'),
    (str(uuid.uuid4()), "Article 12", "Record-Keeping", "AI systems shall be designed to automatically record events (logs)", '["HIGH"]'),
    (str(uuid.uuid4()), "Article 13", "Transparency", "AI systems shall be designed to ensure their operation is sufficiently transparent", '["HIGH", "LIMITED"]'),
    (str(uuid.uuid4()), "Article 14", "Human Oversight", "AI systems shall be designed to allow for effective human oversight", '["HIGH"]'),
    (str(uuid.uuid4()), "Article 15", "Accuracy & Robustness", "AI systems shall achieve appropriate levels of accuracy, robustness and cybersecurity", '["HIGH"]'),
    (str(uuid.uuid4()), "Article 17", "Quality Management", "Providers shall put a quality management system in place", '["HIGH"]'),
    (str(uuid.uuid4()), "Article 52", "Transparency Obligations", "Providers shall ensure AI systems intended to interact with persons are designed to inform users", '["LIMITED", "MINIMAL"]'),
    (str(uuid.uuid4()), "Article 61", "Post-Market Monitoring", "Providers shall establish a post-market monitoring system", '["HIGH"]'),
    
    # NIST AI RMF requirements
    (str(uuid.uuid4()), "MAP 1.1", "AI System Context", "Intended purpose, operational context, and assumptions are documented", '["HIGH", "LIMITED", "MINIMAL"]'),
    (str(uuid.uuid4()), "MAP 1.5", "Risk Identification", "Organizational risk tolerances are determined and documented", '["HIGH", "LIMITED"]'),
    (str(uuid.uuid4()), "MEASURE 2.3", "Performance Metrics", "AI system performance metrics are defined and documented", '["HIGH", "LIMITED"]'),
    (str(uuid.uuid4()), "MEASURE 2.6", "Bias Assessment", "Computational bias assessment is performed and documented", '["HIGH"]'),
    (str(uuid.uuid4()), "MANAGE 3.1", "Risk Response", "Risk response options are identified and documented", '["HIGH", "LIMITED"]'),
    (str(uuid.uuid4()), "MANAGE 4.1", "Deployment Controls", "Deployment controls are established and documented", '["HIGH"]'),
    (str(uuid.uuid4()), "GOVERN 1.1", "Governance Framework", "AI governance framework is established", '["HIGH", "LIMITED", "MINIMAL"]'),
    (str(uuid.uuid4()), "GOVERN 1.2", "Accountability", "Accountability structures are in place", '["HIGH", "LIMITED"]'),
    
    # ISO 42001 requirements
    (str(uuid.uuid4()), "Section 5.1", "Leadership Commitment", "Top management demonstrates leadership and commitment", '["HIGH", "LIMITED", "MINIMAL"]'),
    (str(uuid.uuid4()), "Section 6.1", "Risk Assessment", "Organization determines risks and opportunities", '["HIGH", "LIMITED"]'),
    (str(uuid.uuid4()), "Section 7.2", "Competence", "Persons doing work affecting AI system performance are competent", '["HIGH", "LIMITED"]'),
    (str(uuid.uuid4()), "Section 8.1", "Operational Planning", "Organization plans, implements and controls processes", '["HIGH"]'),
    (str(uuid.uuid4()), "Section 9.1", "Monitoring & Measurement", "Organization determines what needs to be monitored", '["HIGH", "LIMITED"]'),
]

print("\nInserting requirements...")
for req in requirements:
    cur.execute("""
        INSERT INTO compliance_requirements (id, article, title, description, applies_to)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
    """, req)
print(f"✓ Inserted {len(requirements)} requirements")

conn.commit()

# Get requirement IDs for mapping
cur.execute("SELECT id, article FROM compliance_requirements")
req_map = {row[1]: row[0] for row in cur.fetchall()}

# ============================================
# 2. SEED REQUIREMENT-FRAMEWORK MAPPINGS
# ============================================
print("\nMapping requirements to frameworks...")

framework_mappings = [
    # EU AI Act mappings
    (req_map.get("Article 9"), eu_ai_act_id, "Art. 9"),
    (req_map.get("Article 10"), eu_ai_act_id, "Art. 10"),
    (req_map.get("Article 11"), eu_ai_act_id, "Art. 11"),
    (req_map.get("Article 12"), eu_ai_act_id, "Art. 12"),
    (req_map.get("Article 13"), eu_ai_act_id, "Art. 13"),
    (req_map.get("Article 14"), eu_ai_act_id, "Art. 14"),
    (req_map.get("Article 15"), eu_ai_act_id, "Art. 15"),
    (req_map.get("Article 17"), eu_ai_act_id, "Art. 17"),
    (req_map.get("Article 52"), eu_ai_act_id, "Art. 52"),
    (req_map.get("Article 61"), eu_ai_act_id, "Art. 61"),
    
    # NIST AI RMF mappings
    (req_map.get("MAP 1.1"), nist_id, "MAP 1.1"),
    (req_map.get("MAP 1.5"), nist_id, "MAP 1.5"),
    (req_map.get("MEASURE 2.3"), nist_id, "MEASURE 2.3"),
    (req_map.get("MEASURE 2.6"), nist_id, "MEASURE 2.6"),
    (req_map.get("MANAGE 3.1"), nist_id, "MANAGE 3.1"),
    (req_map.get("MANAGE 4.1"), nist_id, "MANAGE 4.1"),
    (req_map.get("GOVERN 1.1"), nist_id, "GOVERN 1.1"),
    (req_map.get("GOVERN 1.2"), nist_id, "GOVERN 1.2"),
    
    # ISO 42001 mappings
    (req_map.get("Section 5.1"), iso_id, "§5.1"),
    (req_map.get("Section 6.1"), iso_id, "§6.1"),
    (req_map.get("Section 7.2"), iso_id, "§7.2"),
    (req_map.get("Section 8.1"), iso_id, "§8.1"),
    (req_map.get("Section 9.1"), iso_id, "§9.1"),
    
    # Cross-framework mappings (some requirements map to multiple)
    (req_map.get("Article 9"), nist_id, "MAP 1.5"),
    (req_map.get("Article 13"), nist_id, "MAP 1.1"),
    (req_map.get("Article 14"), iso_id, "§8.1"),
    (req_map.get("GOVERN 1.1"), iso_id, "§5.1"),
]

for req_id, fw_id, article_ref in framework_mappings:
    if req_id and fw_id:
        cur.execute("""
            INSERT INTO requirement_framework_map (id, requirement_id, framework_id, article_ref)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (str(uuid.uuid4()), req_id, fw_id, article_ref))

print(f"✓ Created {len(framework_mappings)} framework mappings")
conn.commit()

# ============================================
# 3. SEED AI SYSTEMS
# ============================================
print("\nCreating AI systems...")

systems = [
    (str(uuid.uuid4()), "PatchIQ7", "HR screening & candidate ranking", "HIGH", "Meridian Financial Group", "Human Resources", "hr@meridian.com"),
    (str(uuid.uuid4()), "RecruitAI", "Resume parsing & matching engine", "HIGH", "Meridian Financial Group", "Human Resources", "recruiting@meridian.com"),
    (str(uuid.uuid4()), "SupportBot", "AI chat assistant for tier-1 support", "LIMITED", "Meridian Financial Group", "Customer Service", "support@meridian.com"),
]

for sys in systems:
    cur.execute("""
        INSERT INTO ai_systems (id, name, description, risk_category, organization, department, owner_email, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
        ON CONFLICT DO NOTHING
    """, sys)

print(f"✓ Created {len(systems)} AI systems")
conn.commit()

# Get system IDs
cur.execute("SELECT id, name FROM ai_systems")
system_map = {row[1]: row[0] for row in cur.fetchall()}

# ============================================
# 4. SEED REQUIREMENT MAPPINGS (system <-> requirement)
# ============================================
print("\nMapping requirements to systems...")

statuses = ['COMPLETED', 'IN_PROGRESS', 'NOT_STARTED', 'NON_COMPLIANT']

import random
random.seed(42)

mapping_count = 0
for system_name, system_id in system_map.items():
    cur.execute("SELECT risk_category FROM ai_systems WHERE id = %s", (system_id,))
    risk = cur.fetchone()[0]
    
    cur.execute("""
        SELECT id, article FROM compliance_requirements 
        WHERE applies_to::text LIKE %s
    """, (f'%{risk}%',))
    applicable_reqs = cur.fetchall()
    
    for req_id, article in applicable_reqs:
        if system_name == "PatchIQ7":
            status = random.choices(statuses, weights=[30, 25, 40, 5])[0]
        elif system_name == "RecruitAI":
            status = random.choices(statuses, weights=[44, 30, 20, 6])[0]
        else:
            status = random.choices(statuses, weights=[61, 20, 15, 4])[0]
        
        cur.execute("""
            INSERT INTO requirement_mappings (id, ai_system_id, requirement_id, status, created_at, updated_at)
            VALUES (%s, %s, %s, %s, NOW(), NOW())
            ON CONFLICT DO NOTHING
        """, (str(uuid.uuid4()), system_id, req_id, status))
        mapping_count += 1

print(f"✓ Created {mapping_count} requirement mappings")
conn.commit()

# ============================================
# 5. SEED COMPLIANCE EVENTS (Activity Feed)
# ============================================
print("\nCreating compliance events...")

import json

events = [
    {
        "system_id": system_map.get("PatchIQ7"),
        "event_type": "model_retrain",
        "title": "Model retraining detected. Re-evaluation triggered for transparency documentation requirements.",
        "severity": "alert",
        "framework_refs": json.dumps([
            {"framework_id": eu_ai_act_id, "article_ref": "Art. 13"},
            {"framework_id": nist_id, "article_ref": "MAP 1.1"}
        ]),
        "hours_ago": 2
    },
    {
        "system_id": system_map.get("RecruitAI"),
        "event_type": "requirement_completed",
        "title": "Human oversight controls validated. Requirement marked as complete.",
        "severity": "success",
        "framework_refs": json.dumps([
            {"framework_id": eu_ai_act_id, "article_ref": "Art. 14"},
            {"framework_id": iso_id, "article_ref": "§6.1"}
        ]),
        "hours_ago": 5
    },
    {
        "system_id": system_map.get("SupportBot"),
        "event_type": "config_change",
        "title": "Data pipeline configuration changed. Risk assessment re-evaluation pending.",
        "severity": "warning",
        "framework_refs": json.dumps([
            {"framework_id": nist_id, "article_ref": "MEASURE 2.3"}
        ]),
        "hours_ago": 8
    },
    {
        "system_id": system_map.get("PatchIQ7"),
        "event_type": "evidence_uploaded",
        "title": "Bias monitoring report generated. Cross-framework review available.",
        "severity": "info",
        "framework_refs": json.dumps([
            {"framework_id": eu_ai_act_id, "article_ref": "Art. 10"},
            {"framework_id": nist_id, "article_ref": "MEASURE 2.6"},
            {"framework_id": iso_id, "article_ref": "§9.1"}
        ]),
        "hours_ago": 24
    },
]

for event in events:
    created_at = datetime.utcnow() - timedelta(hours=event["hours_ago"])
    cur.execute("""
        INSERT INTO compliance_events (id, system_id, event_type, title, severity, framework_refs, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (
        str(uuid.uuid4()),
        event["system_id"],
        event["event_type"],
        event["title"],
        event["severity"],
        event["framework_refs"],
        created_at
    ))

print(f"✓ Created {len(events)} compliance events")
conn.commit()

# ============================================
# VERIFY
# ============================================
print("\n" + "="*50)
print("SEED COMPLETE - Verification:")
print("="*50)

tables = ['ai_systems', 'compliance_requirements', 'frameworks', 'requirement_framework_map', 'compliance_events', 'requirement_mappings']
for t in tables:
    cur.execute(f'SELECT COUNT(*) FROM {t}')
    print(f"  {t}: {cur.fetchone()[0]} rows")

cur.close()
conn.close()
print("\n✅ Database seeded successfully!")

