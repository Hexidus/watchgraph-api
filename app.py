from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import os
from sqlalchemy.orm import Session
from database import get_db, init_db
from models import AISystem, ComplianceRequirement, RiskCategory, ComplianceStatus
from pydantic import BaseModel, Field
from typing import List, Optional

# Pydantic schemas for request/response validation
class AISystemCreate(BaseModel):
    """Schema for creating a new AI system"""
    name: str = Field(..., min_length=1, max_length=255, description="Name of the AI system")
    description: Optional[str] = Field(None, description="Detailed description")
    risk_category: RiskCategory = Field(..., description="EU AI Act risk category")
    organization: Optional[str] = Field(None, max_length=255)
    department: Optional[str] = Field(None, max_length=255)
    owner_email: Optional[str] = Field(None, max_length=255)
    
    class Config:
        use_enum_values = True

class AISystemResponse(BaseModel):
    """Schema for AI system responses"""
    id: str
    name: str
    description: Optional[str]
    risk_category: str
    organization: Optional[str]
    department: Optional[str]
    owner_email: Optional[str]
    created_at: str
    updated_at: str
    
    class Config:
        from_attributes = True

class RequirementStatusUpdate(BaseModel):
    """Schema for updating requirement status"""
    status: ComplianceStatus = Field(..., description="New compliance status")
    notes: Optional[str] = Field(None, description="Notes about this requirement or status change")
    updated_by: Optional[str] = Field(None, max_length=255, description="Email of person updating")
    
    class Config:
        use_enum_values = True

app = FastAPI(
    title="WatchGraph API",
    description="Continuous AI Compliance Monitoring Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    init_db()
    print("🚀 WatchGraph API started successfully!")

@app.get("/")
async def home():
    """Main endpoint for WatchGraph continuous AI compliance monitoring"""
    return {
        "message": "Hello from WatchGraph - Continuous AI Compliance Monitoring Platform",
        "company": "Hexidus",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
        "description": "Real-time monitoring and compliance checking for AI systems"
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "WatchGraph API",
        "timestamp": datetime.utcnow().isoformat(),
        "uptime": "operational"
    }

@app.get("/version")
async def version():
    """Version information endpoint"""
    return {
        "service": "WatchGraph",
        "version": "1.0.0",
        "platform": "Continuous AI Compliance Monitoring",
        "company": "Hexidus",
        "environment": os.getenv("ENVIRONMENT", "development")
    }

# AI Systems Endpoints
@app.post("/api/systems", response_model=AISystemResponse, status_code=201)
async def create_ai_system(
    system: AISystemCreate,
    db: Session = Depends(get_db)
):
    """
    Register a new AI system for compliance monitoring
    
    Automatically assigns applicable EU AI Act requirements based on risk category.
    
    - **name**: Name of the AI system (required)
    - **risk_category**: EU AI Act risk category (required)
        - unacceptable: Prohibited AI systems
        - high: High-risk AI systems
        - limited: Limited risk (transparency obligations)
        - minimal: Minimal/no risk
    - **description**: Detailed description of the system
    - **organization**: Organization name
    - **department**: Department or team
    - **owner_email**: Contact email for the system owner
    """
    import json
    from models import RequirementMapping
    
    # Create new AI system
    db_system = AISystem(
        name=system.name,
        description=system.description,
        risk_category=system.risk_category,
        organization=system.organization,
        department=system.department,
        owner_email=system.owner_email
    )
    
    db.add(db_system)
    db.commit()
    db.refresh(db_system)
    
    # Automatically assign applicable requirements based on risk category
    applicable_requirements = db.query(ComplianceRequirement).all()
    
    requirements_assigned = 0
    for requirement in applicable_requirements:
        # Parse the applies_to JSON field
        applies_to = json.loads(requirement.applies_to)
        
        # Check if this requirement applies to the system's risk category
        if system.risk_category in applies_to:
            mapping = RequirementMapping(
                ai_system_id=db_system.id,
                requirement_id=requirement.id,
                status=ComplianceStatus.NOT_STARTED
            )
            db.add(mapping)
            requirements_assigned += 1
    
    db.commit()
    
    print(f"✅ Created AI system '{db_system.name}' with {requirements_assigned} requirements assigned")
    
    # Convert to response format
    return AISystemResponse(
        id=db_system.id,
        name=db_system.name,
        description=db_system.description,
        risk_category=db_system.risk_category.value,
        organization=db_system.organization,
        department=db_system.department,
        owner_email=db_system.owner_email,
        created_at=db_system.created_at.isoformat(),
        updated_at=db_system.updated_at.isoformat()
    )

@app.get("/api/systems", response_model=List[AISystemResponse])
async def list_ai_systems(db: Session = Depends(get_db)):
    """
    List all registered AI systems
    
    Returns a list of all AI systems being monitored for compliance.
    """
    systems = db.query(AISystem).all()
    
    return [
        AISystemResponse(
            id=s.id,
            name=s.name,
            description=s.description,
            risk_category=s.risk_category.value,
            organization=s.organization,
            department=s.department,
            owner_email=s.owner_email,
            created_at=s.created_at.isoformat(),
            updated_at=s.updated_at.isoformat()
        )
        for s in systems
    ]

@app.get("/api/systems/{system_id}", response_model=AISystemResponse)
async def get_ai_system(system_id: str, db: Session = Depends(get_db)):
    """
    Get details of a specific AI system
    
    - **system_id**: UUID of the AI system
    """
    system = db.query(AISystem).filter(AISystem.id == system_id).first()
    
    if not system:
        raise HTTPException(status_code=404, detail="AI system not found")
    
    return AISystemResponse(
        id=system.id,
        name=system.name,
        description=system.description,
        risk_category=system.risk_category.value,
        organization=system.organization,
        department=system.department,
        owner_email=system.owner_email,
        created_at=system.created_at.isoformat(),
        updated_at=system.updated_at.isoformat()
    )

# Requirements Endpoints
@app.get("/api/requirements")
async def list_requirements(db: Session = Depends(get_db)):
    """
    List all EU AI Act compliance requirements
    
    Returns all available compliance requirements in the system.
    """
    requirements = db.query(ComplianceRequirement).all()
    
    import json
    return [
        {
            "id": req.id,
            "article": req.article,
            "title": req.title,
            "description": req.description,
            "applies_to": json.loads(req.applies_to)
        }
        for req in requirements
    ]

@app.get("/api/systems/{system_id}/requirements")
async def get_system_requirements(system_id: str, db: Session = Depends(get_db)):
    """
    Get all compliance requirements for a specific AI system
    
    Returns requirements with their current compliance status.
    """
    from models import RequirementMapping
    
    # Check if system exists
    system = db.query(AISystem).filter(AISystem.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="AI system not found")
    
    # Get all requirement mappings for this system
    mappings = db.query(RequirementMapping).filter(
        RequirementMapping.ai_system_id == system_id
    ).all()
    
    results = []
    for mapping in mappings:
        requirement = db.query(ComplianceRequirement).filter(
            ComplianceRequirement.id == mapping.requirement_id
        ).first()
        
        if requirement:
            import json
            results.append({
                "mapping_id": mapping.id,
                "requirement_id": requirement.id,
                "article": requirement.article,
                "title": requirement.title,
                "description": requirement.description,
                "status": mapping.status.value,
                "notes": mapping.notes,
                "updated_at": mapping.updated_at.isoformat()
            })
    
    return results

@app.get("/api/systems/{system_id}/compliance")
async def get_system_compliance(system_id: str, db: Session = Depends(get_db)):
    """
    Get compliance status overview for an AI system
    
    Returns compliance percentage and requirement breakdown.
    """
    from models import RequirementMapping
    
    # Check if system exists
    system = db.query(AISystem).filter(AISystem.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="AI system not found")
    
    # Get all requirement mappings
    mappings = db.query(RequirementMapping).filter(
        RequirementMapping.ai_system_id == system_id
    ).all()
    
    total_requirements = len(mappings)
    if total_requirements == 0:
        return {
            "system_id": system_id,
            "system_name": system.name,
            "risk_category": system.risk_category.value,
            "total_requirements": 0,
            "compliance_percentage": 0,
            "status_breakdown": {}
        }
    
    # Calculate status breakdown
    status_counts = {
        "not_started": 0,
        "in_progress": 0,
        "completed": 0,
        "non_compliant": 0
    }
    
    for mapping in mappings:
        status_counts[mapping.status.value] += 1
    
    # Calculate compliance percentage (completed / total)
    compliance_percentage = (status_counts["completed"] / total_requirements) * 100
    
    return {
        "system_id": system_id,
        "system_name": system.name,
        "risk_category": system.risk_category.value,
        "total_requirements": total_requirements,
        "compliance_percentage": round(compliance_percentage, 2),
        "status_breakdown": status_counts,
        "requirements_completed": status_counts["completed"],
        "requirements_in_progress": status_counts["in_progress"],
        "requirements_not_started": status_counts["not_started"],
        "requirements_non_compliant": status_counts["non_compliant"]
    }

# Requirement Status Update Endpoint
@app.put("/api/requirements/{mapping_id}")
async def update_requirement_status(
    mapping_id: str,
    update: RequirementStatusUpdate,
    db: Session = Depends(get_db)
):
    """
    Update the compliance status of a requirement
    
    Allows updating the status, notes, and tracking who made the change.
    
    - **mapping_id**: UUID of the requirement mapping
    - **status**: New status (not_started, in_progress, completed, non_compliant)
    - **notes**: Optional notes about the requirement or change
    - **updated_by**: Email of person making the update
    """
    from models import RequirementMapping
    
    # Find the requirement mapping
    mapping = db.query(RequirementMapping).filter(
        RequirementMapping.id == mapping_id
    ).first()
    
    if not mapping:
        raise HTTPException(status_code=404, detail="Requirement mapping not found")
    
    # Store old status for logging
    old_status = mapping.status.value
    
    # Update the mapping
    mapping.status = ComplianceStatus(update.status)
    if update.notes is not None:
        mapping.notes = update.notes
    if update.updated_by is not None:
        mapping.updated_by = update.updated_by
    
    db.commit()
    db.refresh(mapping)
    
    # Get the requirement details for response
    requirement = db.query(ComplianceRequirement).filter(
        ComplianceRequirement.id == mapping.requirement_id
    ).first()
    
    print(f"✅ Requirement '{requirement.title}' status changed: {old_status} → {update.status}")
    
    import json
    return {
        "mapping_id": mapping.id,
        "requirement_id": requirement.id,
        "article": requirement.article,
        "title": requirement.title,
        "old_status": old_status,
        "new_status": mapping.status.value,
        "notes": mapping.notes,
        "updated_by": mapping.updated_by,
        "updated_at": mapping.updated_at.isoformat()
    }

@app.get("/api/compliance")
async def compliance():
    """Future endpoint for compliance rule management"""
    return {
        "message": "Compliance Rules endpoint - Coming soon",
        "description": "Define and manage compliance rules for AI systems",
        "status": "under_development"
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
