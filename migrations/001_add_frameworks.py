"""
Database Migration: Add Multi-Framework Support
"""

import os
import uuid
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://watchgraph:watchgraph@localhost:5432/watchgraph")

def run_migration():
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as conn:
        print("🚀 Starting migration: Add Multi-Framework Support")
        
        print("\n📦 Creating frameworks table...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS frameworks (
                id VARCHAR(36) PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                short_code VARCHAR(20) NOT NULL UNIQUE,
                version VARCHAR(20),
                description TEXT,
                color VARCHAR(7),
                created_at TIMESTAMP DEFAULT NOW()
            );
        """))
        print("   ✓ frameworks table created")
        
        print("\n📦 Creating requirement_framework_map table...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS requirement_framework_map (
                id VARCHAR(36) PRIMARY KEY,
                requirement_id VARCHAR(36) REFERENCES compliance_requirements(id) ON DELETE CASCADE,
                framework_id VARCHAR(36) REFERENCES frameworks(id) ON DELETE CASCADE,
                article_ref VARCHAR(50),
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(requirement_id, framework_id)
            );
        """))
        print("   ✓ requirement_framework_map table created")
        
        print("\n📦 Creating compliance_events table...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS compliance_events (
                id VARCHAR(36) PRIMARY KEY,
                system_id VARCHAR(36) REFERENCES ai_systems(id) ON DELETE SET NULL,
                event_type VARCHAR(30) NOT NULL,
                title VARCHAR(200) NOT NULL,
                description TEXT,
                severity VARCHAR(10) DEFAULT 'info',
                framework_refs JSONB DEFAULT '[]',
                tenant_id VARCHAR(36),
                created_at TIMESTAMP DEFAULT NOW()
            );
        """))
        print("   ✓ compliance_events table created")
        
        print("\n📦 Adding tenant_id to existing tables...")
        result = conn.execute(text("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name = 'ai_systems' AND column_name = 'tenant_id';
        """))
        if not result.fetchone():
            conn.execute(text("ALTER TABLE ai_systems ADD COLUMN tenant_id VARCHAR(36);"))
            print("   ✓ tenant_id added to ai_systems")
        else:
            print("   ○ tenant_id already exists in ai_systems")
        
        result = conn.execute(text("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name = 'compliance_requirements' AND column_name = 'tenant_id';
        """))
        if not result.fetchone():
            conn.execute(text("ALTER TABLE compliance_requirements ADD COLUMN tenant_id VARCHAR(36);"))
            print("   ✓ tenant_id added to compliance_requirements")
        else:
            print("   ○ tenant_id already exists in compliance_requirements")
        
        print("\n📦 Creating indexes...")
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_rfm_requirement ON requirement_framework_map(requirement_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_rfm_framework ON requirement_framework_map(framework_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_events_system ON compliance_events(system_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_events_created ON compliance_events(created_at DESC);"))
        print("   ✓ Indexes created")
        
        conn.commit()
        print("\n✅ Migration completed!")

def seed_frameworks():
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as conn:
        print("\n🌱 Seeding frameworks...")
        
        result = conn.execute(text("SELECT COUNT(*) FROM frameworks;"))
        if result.fetchone()[0] > 0:
            print("   ○ Frameworks already seeded")
            return
        
        frameworks = [
            (str(uuid.uuid4()), "EU AI Act", "eu-ai-act", "2024", "European Union AI Act", "#3b82f6"),
            (str(uuid.uuid4()), "NIST AI RMF", "nist-ai-rmf", "1.0", "NIST AI Risk Management Framework", "#ec4899"),
            (str(uuid.uuid4()), "ISO 42001", "iso-42001", "2023", "ISO/IEC 42001 AI Management System", "#6366f1"),
        ]
        
        for fw in frameworks:
            conn.execute(text("""
                INSERT INTO frameworks (id, name, short_code, version, description, color)
                VALUES (:id, :name, :code, :ver, :desc, :color)
            """), {"id": fw[0], "name": fw[1], "code": fw[2], "ver": fw[3], "desc": fw[4], "color": fw[5]})
            print(f"   ✓ Added: {fw[1]}")
        
        conn.commit()
        print("✅ Frameworks seeded!")

def map_requirements():
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as conn:
        print("\n🔗 Mapping requirements to EU AI Act...")
        
        result = conn.execute(text("SELECT id FROM frameworks WHERE short_code = 'eu-ai-act';"))
        row = result.fetchone()
        if not row:
            print("   ✗ EU AI Act not found")
            return
        
        eu_id = row[0]
        
        result = conn.execute(text("SELECT id, article FROM compliance_requirements;"))
        requirements = result.fetchall()
        
        count = 0
        for req_id, article in requirements:
            exists = conn.execute(text("""
                SELECT 1 FROM requirement_framework_map WHERE requirement_id = :rid AND framework_id = :fid
            """), {"rid": req_id, "fid": eu_id}).fetchone()
            
            if not exists:
                conn.execute(text("""
                    INSERT INTO requirement_framework_map (id, requirement_id, framework_id, article_ref)
                    VALUES (:id, :rid, :fid, :art)
                """), {"id": str(uuid.uuid4()), "rid": req_id, "fid": eu_id, "art": article})
                count += 1
        
        conn.commit()
        print(f"   ✓ Mapped {count} requirements to EU AI Act")

if __name__ == "__main__":
    run_migration()
    seed_frameworks()
    map_requirements()