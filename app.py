from auth import get_current_user, verify_token
from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Form, Security, Query
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import os
import uuid
import json
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import get_db, init_db
from models import (
    AISystem, ComplianceRequirement, RiskCategory, ComplianceStatus,
    RequirementMapping, Evidence, EvidenceStatus,
    # NEW: Framework support
    Framework, RequirementFrameworkMap, ComplianceEvent, EventType, EventSeverity
)
from s3_service import (
    generate_s3_key,
    upload_file_to_s3,
    generate_presigned_download_url,
    delete_file_from_s3,
    MIME_TYPE_MAP,
    ALLOWED_FILE_TYPES,
    MAX_FILE_SIZE
)
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

class EvidenceResponse(BaseModel):
    """Schema for evidence response"""
    id: str
    ai_system_id: str
    requirement_mapping_id: Optional[str]
    file_name: str
    file_type: str
    file_size: int
    status: str
    description: Optional[str]
    expiration_date: Optional[str]
    uploaded_by: Optional[str]
    created_at: str
    
    class Config:
        from_attributes = True

# NEW: Schema for compliance events
class ComplianceEventCreate(BaseModel):
    """Schema for creating compliance events"""
    system_id: Optional[str] = None
    event_type: str
    title: str
    description: Optional[str] = None
    severity: str = "info"
    framework_refs: List[dict] = []

app = FastAPI(
    title="WatchGraph API",
    description="Continuous AI Compliance Monitoring Platform",
    version="1.1.0",  # Updated version
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    init_db()
    print("🚀 WatchGraph API v1.1.0 started - Multi-framework support enabled!")

@app.get("/")
async def home():
    """Main endpoint for WatchGraph continuous AI compliance monitoring"""
    return {
        "message": "Hello from WatchGraph - Continuous AI Compliance Monitoring Platform",
        "company": "Hexidus",
        "version": "1.1.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
        "description": "Real-time monitoring and compliance checking for AI systems",
        "features": ["Multi-framework support", "EU AI Act", "NIST AI RMF", "ISO 42001"]
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
        "version": "1.1.0",
        "platform": "Continuous AI Compliance Monitoring",
        "company": "Hexidus",
        "environment": os.getenv("ENVIRONMENT", "development")
    }

# ============================================
# NEW: FRAMEWORK ENDPOINTS
# ============================================

@app.get("/api/frameworks")
async def list_frameworks(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List all compliance frameworks with requirement counts
    
    Returns frameworks like EU AI Act, NIST AI RMF, ISO 42001
    """
    frameworks = db.query(Framework).all()
    
    result = []
    for fw in frameworks:
        # Count requirements mapped to this framework
        req_count = db.query(RequirementFrameworkMap).filter(
            RequirementFrameworkMap.framework_id == fw.id
        ).count()
        
        result.append({
            "id": fw.id,
            "name": fw.name,
            "short_code": fw.short_code,
            "version": fw.version,
            "description": fw.description,
            "color": fw.color,
            "requirement_count": req_count
        })
    
    return result

@app.get("/api/frameworks/{framework_id}")
async def get_framework(
    framework_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get details of a specific framework"""
    framework = db.query(Framework).filter(Framework.id == framework_id).first()
    
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")
    
    req_count = db.query(RequirementFrameworkMap).filter(
        RequirementFrameworkMap.framework_id == framework.id
    ).count()
    
    return {
        "id": framework.id,
        "name": framework.name,
        "short_code": framework.short_code,
        "version": framework.version,
        "description": framework.description,
        "color": framework.color,
        "requirement_count": req_count
    }

# ============================================
# NEW: COMPLIANCE BY FRAMEWORK (for donut chart)
# ============================================

@app.get("/api/compliance/by-framework")
async def get_compliance_by_framework(
    system_id: Optional[str] = Query(None, description="Filter by AI system"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get compliance percentage grouped by framework for donut chart
    
    Returns overall compliance and per-framework breakdown
    """
    frameworks = db.query(Framework).all()
    
    # Base query for requirement mappings
    base_query = db.query(RequirementMapping)
    if system_id:
        base_query = base_query.filter(RequirementMapping.ai_system_id == system_id)
    
    # Calculate overall compliance
    total_mappings = base_query.count()
    completed_mappings = base_query.filter(
        RequirementMapping.status == ComplianceStatus.COMPLETED
    ).count()
    
    overall_compliance = 0
    if total_mappings > 0:
        overall_compliance = round((completed_mappings / total_mappings) * 100, 1)
    
    # Calculate per-framework compliance
    framework_data = []
    for fw in frameworks:
        # Get requirement IDs for this framework
        framework_req_ids = db.query(RequirementFrameworkMap.requirement_id).filter(
            RequirementFrameworkMap.framework_id == fw.id
        ).subquery()
        
        # Count total and completed for this framework
        fw_query = base_query.filter(
            RequirementMapping.requirement_id.in_(framework_req_ids)
        )
        
        fw_total = fw_query.count()
        fw_completed = fw_query.filter(
            RequirementMapping.status == ComplianceStatus.COMPLETED
        ).count()
        
        fw_compliance = 0
        if fw_total > 0:
            fw_compliance = round((fw_completed / fw_total) * 100, 1)
        
        framework_data.append({
            "id": fw.id,
            "name": fw.name,
            "short_code": fw.short_code,
            "color": fw.color,
            "total_requirements": fw_total,
            "completed": fw_completed,
            "compliance_pct": fw_compliance
        })
    
    return {
        "overall_compliance": overall_compliance,
        "total_requirements": total_mappings,
        "completed_requirements": completed_mappings,
        "frameworks": framework_data
    }

# ============================================
# NEW: ACTIVITY FEED ENDPOINTS
# ============================================

@app.get("/api/compliance/activity-feed")
async def get_activity_feed(
    limit: int = Query(20, ge=1, le=100, description="Number of events to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    severity: Optional[str] = Query(None, description="Filter by severity: info, warning, alert, success"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get recent compliance events for the activity feed
    
    Returns chronological list of compliance events with framework tags
    """
    query = db.query(ComplianceEvent)
    
    # Apply severity filter
    if severity:
        try:
            severity_enum = EventSeverity(severity)
            query = query.filter(ComplianceEvent.severity == severity_enum)
        except ValueError:
            pass  # Invalid severity, ignore filter
    
    # Get total count before pagination
    total = query.count()
    
    # Order by most recent and paginate
    events = query.order_by(ComplianceEvent.created_at.desc()) \
        .offset(offset) \
        .limit(limit) \
        .all()
    
    result = []
    for event in events:
        # Get system name if exists
        system_name = None
        if event.system_id:
            system = db.query(AISystem).filter(AISystem.id == event.system_id).first()
            if system:
                system_name = system.name
        
        # Process framework refs
        framework_tags = []
        if event.framework_refs:
            for ref in event.framework_refs:
                fw = db.query(Framework).filter(Framework.id == ref.get("framework_id")).first()
                if fw:
                    framework_tags.append({
                        "short_code": fw.short_code,
                        "name": fw.name,
                        "color": fw.color,
                        "article_ref": ref.get("article_ref")
                    })
        
        result.append({
            "id": event.id,
            "system_id": event.system_id,
            "system_name": system_name,
            "event_type": event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type),
            "title": event.title,
            "description": event.description,
            "severity": event.severity.value if hasattr(event.severity, 'value') else str(event.severity),
            "frameworks": framework_tags,
            "created_at": event.created_at.isoformat()
        })
    
    return {
        "events": result,
        "total": total,
        "limit": limit,
        "offset": offset
    }

@app.post("/api/compliance/events", status_code=201)
async def create_compliance_event(
    event_data: ComplianceEventCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new compliance event (for activity feed)"""
    try:
        event_type = EventType(event_data.event_type)
    except ValueError:
        event_type = EventType.CONFIG_CHANGE
    
    try:
        severity = EventSeverity(event_data.severity)
    except ValueError:
        severity = EventSeverity.INFO
    
    event = ComplianceEvent(
        id=str(uuid.uuid4()),
        system_id=event_data.system_id,
        event_type=event_type,
        title=event_data.title,
        description=event_data.description,
        severity=severity,
        framework_refs=event_data.framework_refs
    )
    
    db.add(event)
    db.commit()
    db.refresh(event)
    
    return {
        "id": event.id,
        "event_type": event.event_type.value,
        "title": event.title,
        "severity": event.severity.value,
        "created_at": event.created_at.isoformat()
    }

# ============================================
# DASHBOARD ENDPOINT (Updated with framework filter)
# ============================================

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(
    framework_id: Optional[str] = Query(None, description="Filter by framework"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get overall dashboard statistics across all AI systems
    
    Supports optional framework filtering.
    Requires authentication.
    """
    total_systems = db.query(AISystem).count()
    
    # Build requirement query with optional framework filter
    req_query = db.query(RequirementMapping)
    
    if framework_id:
        # Get requirement IDs for this framework
        framework_req_ids = db.query(RequirementFrameworkMap.requirement_id).filter(
            RequirementFrameworkMap.framework_id == framework_id
        ).subquery()
        req_query = req_query.filter(RequirementMapping.requirement_id.in_(framework_req_ids))
    
    total_requirements = req_query.count()
    completed_requirements = req_query.filter(
        RequirementMapping.status == ComplianceStatus.COMPLETED
    ).count()
    
    if total_requirements == 0:
        overall_compliance = 0
    else:
        overall_compliance = round((completed_requirements / total_requirements) * 100, 2)
    
    # Get framework count
    framework_count = db.query(Framework).count()
    
    return {
        "total_systems": total_systems,
        "total_requirements": total_requirements,
        "completed_requirements": completed_requirements,
        "overall_compliance": overall_compliance,
        "framework_count": framework_count,
        "user_email": current_user["email"]
    }

# ============================================
# AI SYSTEMS ENDPOINTS (Updated with framework filter)
# ============================================

@app.post("/api/systems", response_model=AISystemResponse, status_code=201)
async def create_ai_system(
    system: AISystemCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Register a new AI system for compliance monitoring"""
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
    
    applicable_requirements = db.query(ComplianceRequirement).all()
    
    requirements_assigned = 0
    for requirement in applicable_requirements:
        applies_to = json.loads(requirement.applies_to) if isinstance(requirement.applies_to, str) else requirement.applies_to
        if system.risk_category in applies_to:
            mapping = RequirementMapping(
                ai_system_id=db_system.id,
                requirement_id=requirement.id,
                status=ComplianceStatus.NOT_STARTED
            )
            db.add(mapping)
            requirements_assigned += 1
    
    db.commit()
    
    # NEW: Create system created event for activity feed
    try:
        event = ComplianceEvent(
            id=str(uuid.uuid4()),
            system_id=db_system.id,
            event_type=EventType.SYSTEM_CREATED,
            title=f"New AI system registered: {db_system.name}",
            description=f"Risk category: {system.risk_category}. {requirements_assigned} requirements assigned.",
            severity=EventSeverity.INFO
        )
        db.add(event)
        db.commit()
    except Exception as e:
        print(f"Warning: Could not create event: {e}")
    
    print(f"✅ Created AI system '{db_system.name}' with {requirements_assigned} requirements assigned")
    
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
async def list_ai_systems(
    framework_id: Optional[str] = Query(None, description="Filter by framework"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all registered AI systems with optional framework filter"""
    if framework_id:
        # Get systems that have requirements from this framework
        framework_req_ids = db.query(RequirementFrameworkMap.requirement_id).filter(
            RequirementFrameworkMap.framework_id == framework_id
        ).subquery()
        
        system_ids = db.query(RequirementMapping.ai_system_id).filter(
            RequirementMapping.requirement_id.in_(framework_req_ids)
        ).distinct().subquery()
        
        systems = db.query(AISystem).filter(AISystem.id.in_(system_ids)).all()
    else:
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
async def get_ai_system(
    system_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get details of a specific AI system"""
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

@app.delete("/api/systems/{system_id}", status_code=204)
async def delete_ai_system(
    system_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete an AI system and all its associated data"""
    system = db.query(AISystem).filter(AISystem.id == system_id).first()
    
    if not system:
        raise HTTPException(status_code=404, detail="AI system not found")
    
    db.query(Evidence).filter(Evidence.ai_system_id == system_id).delete()
    db.query(RequirementMapping).filter(RequirementMapping.ai_system_id == system_id).delete()
    db.delete(system)
    db.commit()
    
    print(f"✅ AI system '{system.name}' and all associated data deleted")
    
    return None

# ============================================
# REQUIREMENTS ENDPOINTS (Updated with framework info)
# ============================================

@app.get("/api/requirements")
async def list_requirements(
    framework_id: Optional[str] = Query(None, description="Filter by framework"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all compliance requirements with optional framework filter"""
    if framework_id:
        # Get requirements for this framework
        mappings = db.query(RequirementFrameworkMap).filter(
            RequirementFrameworkMap.framework_id == framework_id
        ).all()
        req_ids = [m.requirement_id for m in mappings]
        requirements = db.query(ComplianceRequirement).filter(
            ComplianceRequirement.id.in_(req_ids)
        ).all()
    else:
        requirements = db.query(ComplianceRequirement).all()
    
    return [
        {
            "id": req.id,
            "article": req.article,
            "title": req.title,
            "description": req.description,
            "applies_to": json.loads(req.applies_to) if isinstance(req.applies_to, str) else req.applies_to
        }
        for req in requirements
    ]

@app.get("/api/systems/{system_id}/requirements")
async def get_system_requirements(
    system_id: str,
    framework_id: Optional[str] = Query(None, description="Filter by framework"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all compliance requirements for a specific AI system with optional framework filter"""
    system = db.query(AISystem).filter(AISystem.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="AI system not found")
    
    mappings_query = db.query(RequirementMapping).filter(
        RequirementMapping.ai_system_id == system_id
    )
    
    # Apply framework filter if provided
    if framework_id:
        framework_req_ids = db.query(RequirementFrameworkMap.requirement_id).filter(
            RequirementFrameworkMap.framework_id == framework_id
        ).subquery()
        mappings_query = mappings_query.filter(
            RequirementMapping.requirement_id.in_(framework_req_ids)
        )
    
    mappings = mappings_query.all()
    
    results = []
    for mapping in mappings:
        requirement = db.query(ComplianceRequirement).filter(
            ComplianceRequirement.id == mapping.requirement_id
        ).first()
        
        if requirement:
            # NEW: Get framework tags for this requirement
            fw_mappings = db.query(RequirementFrameworkMap).filter(
                RequirementFrameworkMap.requirement_id == requirement.id
            ).all()
            
            frameworks = []
            for fm in fw_mappings:
                fw = db.query(Framework).filter(Framework.id == fm.framework_id).first()
                if fw:
                    frameworks.append({
                        "short_code": fw.short_code,
                        "name": fw.name,
                        "color": fw.color,
                        "article_ref": fm.article_ref
                    })
            
            results.append({
                "mapping_id": mapping.id,
                "requirement_id": requirement.id,
                "article": requirement.article,
                "title": requirement.title,
                "description": requirement.description,
                "status": mapping.status.value,
                "notes": mapping.notes,
                "updated_at": mapping.updated_at.isoformat(),
                "frameworks": frameworks  # NEW: Include framework tags
            })
    
    return results

@app.get("/api/systems/{system_id}/compliance")
async def get_system_compliance(
    system_id: str,
    framework_id: Optional[str] = Query(None, description="Filter by framework"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get compliance status overview for an AI system with optional framework filter"""
    system = db.query(AISystem).filter(AISystem.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="AI system not found")
    
    mappings_query = db.query(RequirementMapping).filter(
        RequirementMapping.ai_system_id == system_id
    )
    
    # Apply framework filter if provided
    if framework_id:
        framework_req_ids = db.query(RequirementFrameworkMap.requirement_id).filter(
            RequirementFrameworkMap.framework_id == framework_id
        ).subquery()
        mappings_query = mappings_query.filter(
            RequirementMapping.requirement_id.in_(framework_req_ids)
        )
    
    mappings = mappings_query.all()
    
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
    
    status_counts = {
        "not_started": 0,
        "in_progress": 0,
        "completed": 0,
        "non_compliant": 0
    }
    
    for mapping in mappings:
        status_counts[mapping.status.value] += 1
    
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

@app.put("/api/requirements/{mapping_id}")
async def update_requirement_status(
    mapping_id: str,
    update: RequirementStatusUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update the compliance status of a requirement"""
    mapping = db.query(RequirementMapping).filter(
        RequirementMapping.id == mapping_id
    ).first()
    
    if not mapping:
        raise HTTPException(status_code=404, detail="Requirement mapping not found")
    
    old_status = mapping.status.value
    
    mapping.status = ComplianceStatus(update.status)
    if update.notes is not None:
        mapping.notes = update.notes
    if update.updated_by is not None:
        mapping.updated_by = update.updated_by
    
    db.commit()
    db.refresh(mapping)
    
    requirement = db.query(ComplianceRequirement).filter(
        ComplianceRequirement.id == mapping.requirement_id
    ).first()
    
    # NEW: Create event for status change (for activity feed)
    try:
        event_type = EventType.REQUIREMENT_COMPLETED if update.status == "completed" else EventType.CONFIG_CHANGE
        severity = EventSeverity.SUCCESS if update.status == "completed" else EventSeverity.INFO
        
        # Get framework refs for this requirement
        fw_mappings = db.query(RequirementFrameworkMap).filter(
            RequirementFrameworkMap.requirement_id == mapping.requirement_id
        ).all()
        framework_refs = [{"framework_id": fm.framework_id, "article_ref": fm.article_ref} for fm in fw_mappings]
        
        event = ComplianceEvent(
            id=str(uuid.uuid4()),
            system_id=mapping.ai_system_id,
            event_type=event_type,
            title=f"{requirement.title}" if requirement else "Requirement updated",
            description=f"Status changed: {old_status} → {update.status}",
            severity=severity,
            framework_refs=framework_refs
        )
        db.add(event)
        db.commit()
    except Exception as e:
        print(f"Warning: Could not create event: {e}")
    
    print(f"✅ Requirement '{requirement.title}' status changed: {old_status} → {update.status}")
    
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

# ============================================
# EVIDENCE ENDPOINTS (Unchanged)
# ============================================

@app.post("/api/requirements/{mapping_id}/evidence", status_code=201)
async def upload_evidence(
    mapping_id: str,
    file: UploadFile = File(..., description="Evidence file (PDF, PNG, JPG, XLSX, DOCX, CSV)"),
    description: Optional[str] = Form(None, description="Description of the evidence"),
    expiration_date: Optional[str] = Form(None, description="Expiration date (YYYY-MM-DD)"),
    uploaded_by: Optional[str] = Form(None, description="Email of uploader"),
    db: Session = Depends(get_db)
):
    """Upload evidence file for a requirement"""
    mapping = db.query(RequirementMapping).filter(RequirementMapping.id == mapping_id).first()
    if not mapping:
        raise HTTPException(status_code=404, detail="Requirement mapping not found")
    
    system = db.query(AISystem).filter(AISystem.id == mapping.ai_system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="AI system not found")
    
    if not file.filename or '.' not in file.filename:
        raise HTTPException(status_code=400, detail="File must have an extension")
    
    file_ext = file.filename.rsplit('.', 1)[1].lower()
    if file_ext not in ALLOWED_FILE_TYPES:
        raise HTTPException(
            status_code=400, 
            detail=f"File type '{file_ext}' not allowed. Allowed: {', '.join(ALLOWED_FILE_TYPES)}"
        )
    
    file_content = await file.read()
    file_size = len(file_content)
    
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400, 
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
        )
    
    if file_size == 0:
        raise HTTPException(status_code=400, detail="File is empty")
    
    s3_key = generate_s3_key(
        organization=system.organization,
        system_id=system.id,
        requirement_mapping_id=mapping_id,
        filename=file.filename
    )
    
    try:
        content_type = MIME_TYPE_MAP.get(file_ext, "application/octet-stream")
        upload_file_to_s3(file_content, s3_key, content_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    exp_date = None
    if expiration_date:
        try:
            exp_date = datetime.strptime(expiration_date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
    
    evidence = Evidence(
        ai_system_id=system.id,
        requirement_mapping_id=mapping_id,
        file_name=file.filename,
        file_type=file_ext,
        file_size=file_size,
        s3_key=s3_key,
        description=description,
        expiration_date=exp_date,
        uploaded_by=uploaded_by,
        status=EvidenceStatus.CURRENT
    )
    
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    
    # NEW: Create event for evidence upload
    try:
        requirement = db.query(ComplianceRequirement).filter(
            ComplianceRequirement.id == mapping.requirement_id
        ).first()
        
        fw_mappings = db.query(RequirementFrameworkMap).filter(
            RequirementFrameworkMap.requirement_id == mapping.requirement_id
        ).all()
        framework_refs = [{"framework_id": fm.framework_id, "article_ref": fm.article_ref} for fm in fw_mappings]
        
        event = ComplianceEvent(
            id=str(uuid.uuid4()),
            system_id=system.id,
            event_type=EventType.EVIDENCE_UPLOADED,
            title=f"Evidence uploaded: {file.filename}",
            description=f"For requirement: {requirement.title}" if requirement else None,
            severity=EventSeverity.SUCCESS,
            framework_refs=framework_refs
        )
        db.add(event)
        db.commit()
    except Exception as e:
        print(f"Warning: Could not create event: {e}")
    
    print(f"✅ Evidence '{file.filename}' uploaded for requirement mapping {mapping_id}")
    
    return {
        "message": f"Successfully uploaded {file.filename}",
        "evidence": {
            "id": evidence.id,
            "file_name": evidence.file_name,
            "file_type": evidence.file_type,
            "file_size": evidence.file_size,
            "status": evidence.status.value,
            "created_at": evidence.created_at.isoformat()
        }
    }

@app.get("/api/requirements/{mapping_id}/evidence")
async def list_requirement_evidence(
    mapping_id: str,
    page: int = 1,
    page_size: int = 20,
    db: Session = Depends(get_db)
):
    """List all evidence for a requirement mapping"""
    mapping = db.query(RequirementMapping).filter(RequirementMapping.id == mapping_id).first()
    if not mapping:
        raise HTTPException(status_code=404, detail="Requirement mapping not found")
    
    page_size = min(page_size, 100)
    
    query = db.query(Evidence).filter(
        Evidence.requirement_mapping_id == mapping_id,
        Evidence.deleted_at.is_(None)
    )
    
    total = query.count()
    
    evidence_list = query.order_by(Evidence.created_at.desc()) \
        .offset((page - 1) * page_size) \
        .limit(page_size) \
        .all()
    
    return {
        "items": [
            {
                "id": e.id,
                "file_name": e.file_name,
                "file_type": e.file_type,
                "file_size": e.file_size,
                "status": e.status.value,
                "description": e.description,
                "expiration_date": e.expiration_date.isoformat() if e.expiration_date else None,
                "uploaded_by": e.uploaded_by,
                "created_at": e.created_at.isoformat()
            }
            for e in evidence_list
        ],
        "total": total,
        "page": page,
        "page_size": page_size
    }

@app.get("/api/systems/{system_id}/evidence")
async def list_system_evidence(
    system_id: str,
    page: int = 1,
    page_size: int = 20,
    db: Session = Depends(get_db)
):
    """List all evidence for an AI system"""
    system = db.query(AISystem).filter(AISystem.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="AI system not found")
    
    page_size = min(page_size, 100)
    
    query = db.query(Evidence).filter(
        Evidence.ai_system_id == system_id,
        Evidence.deleted_at.is_(None)
    )
    
    total = query.count()
    
    evidence_list = query.order_by(Evidence.created_at.desc()) \
        .offset((page - 1) * page_size) \
        .limit(page_size) \
        .all()
    
    return {
        "items": [
            {
                "id": e.id,
                "requirement_mapping_id": e.requirement_mapping_id,
                "file_name": e.file_name,
                "file_type": e.file_type,
                "file_size": e.file_size,
                "status": e.status.value,
                "description": e.description,
                "expiration_date": e.expiration_date.isoformat() if e.expiration_date else None,
                "uploaded_by": e.uploaded_by,
                "created_at": e.created_at.isoformat()
            }
            for e in evidence_list
        ],
        "total": total,
        "page": page,
        "page_size": page_size
    }

@app.get("/api/evidence/{evidence_id}")
async def get_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """Get details of a specific evidence file"""
    evidence = db.query(Evidence).filter(
        Evidence.id == evidence_id,
        Evidence.deleted_at.is_(None)
    ).first()
    
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    return {
        "id": evidence.id,
        "ai_system_id": evidence.ai_system_id,
        "requirement_mapping_id": evidence.requirement_mapping_id,
        "file_name": evidence.file_name,
        "file_type": evidence.file_type,
        "file_size": evidence.file_size,
        "status": evidence.status.value,
        "description": evidence.description,
        "expiration_date": evidence.expiration_date.isoformat() if evidence.expiration_date else None,
        "uploaded_by": evidence.uploaded_by,
        "created_at": evidence.created_at.isoformat(),
        "updated_at": evidence.updated_at.isoformat()
    }

@app.get("/api/evidence/{evidence_id}/download")
async def download_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """Get a pre-signed download URL for evidence"""
    evidence = db.query(Evidence).filter(
        Evidence.id == evidence_id,
        Evidence.deleted_at.is_(None)
    ).first()
    
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    try:
        download_url = generate_presigned_download_url(
            s3_key=evidence.s3_key,
            filename=evidence.file_name,
            expires_in=300
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to generate download URL")
    
    return {
        "download_url": download_url,
        "expires_in_seconds": 300,
        "file_name": evidence.file_name,
        "file_type": evidence.file_type
    }

@app.patch("/api/evidence/{evidence_id}")
async def update_evidence(
    evidence_id: str,
    description: Optional[str] = None,
    expiration_date: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Update evidence metadata"""
    evidence = db.query(Evidence).filter(
        Evidence.id == evidence_id,
        Evidence.deleted_at.is_(None)
    ).first()
    
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    if description is not None:
        evidence.description = description
    
    if expiration_date is not None:
        try:
            evidence.expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
    
    if status is not None:
        try:
            evidence.status = EvidenceStatus(status)
        except ValueError:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid status. Must be one of: {[s.value for s in EvidenceStatus]}"
            )
    
    db.commit()
    db.refresh(evidence)
    
    return {
        "id": evidence.id,
        "file_name": evidence.file_name,
        "status": evidence.status.value,
        "description": evidence.description,
        "expiration_date": evidence.expiration_date.isoformat() if evidence.expiration_date else None,
        "updated_at": evidence.updated_at.isoformat()
    }

@app.delete("/api/evidence/{evidence_id}", status_code=204)
async def delete_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """Delete evidence (soft delete)"""
    evidence = db.query(Evidence).filter(
        Evidence.id == evidence_id,
        Evidence.deleted_at.is_(None)
    ).first()
    
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    evidence.deleted_at = datetime.utcnow()
    db.commit()
    
    print(f"✅ Evidence '{evidence.file_name}' soft deleted")
    
    return None

@app.get("/api/requirements/{mapping_id}/evidence/stats")
async def get_evidence_stats(mapping_id: str, db: Session = Depends(get_db)):
    """Get evidence statistics for a requirement mapping"""
    mapping = db.query(RequirementMapping).filter(RequirementMapping.id == mapping_id).first()
    if not mapping:
        raise HTTPException(status_code=404, detail="Requirement mapping not found")
    
    stats = db.query(
        Evidence.status,
        func.count(Evidence.id)
    ).filter(
        Evidence.requirement_mapping_id == mapping_id,
        Evidence.deleted_at.is_(None)
    ).group_by(Evidence.status).all()
    
    result = {
        "current": 0,
        "expiring_soon": 0,
        "expired": 0,
        "archived": 0,
        "total": 0
    }
    
    for status, count in stats:
        result[status.value] = count
        result["total"] += count
    
    return result

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
