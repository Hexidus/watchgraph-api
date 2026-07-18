from sqlalchemy import Column, String, Integer, DateTime, Enum, ForeignKey, Text, JSON, Date, ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime, date
import enum
import uuid

Base = declarative_base()

class RiskCategory(str, enum.Enum):
    """EU AI Act Risk Categories (Article 6)"""
    UNACCEPTABLE = "unacceptable"  # Prohibited AI systems
    HIGH = "high"                   # High-risk AI systems
    LIMITED = "limited"             # Limited risk (transparency obligations)
    MINIMAL = "minimal"             # Minimal/no risk

class ComplianceStatus(str, enum.Enum):
    """Compliance status for requirements"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    NON_COMPLIANT = "non_compliant"

class EvidenceStatus(str, enum.Enum):
    """Status for evidence lifecycle"""
    CURRENT = "current"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    ARCHIVED = "archived"

class EventSeverity(str, enum.Enum):
    """Severity levels for compliance events"""
    INFO = "info"
    WARNING = "warning"
    ALERT = "alert"
    SUCCESS = "success"

class EventType(str, enum.Enum):
    """Types of compliance events"""
    MODEL_RETRAIN = "model_retrain"
    CONFIG_CHANGE = "config_change"
    REQUIREMENT_COMPLETED = "requirement_completed"
    REQUIREMENT_FAILED = "requirement_failed"
    RISK_REASSESSMENT = "risk_reassessment"
    EVIDENCE_UPLOADED = "evidence_uploaded"
    EVIDENCE_EXPIRED = "evidence_expired"
    SYSTEM_CREATED = "system_created"

# ===========================================
# NEW: Framework Model
# ===========================================

class Framework(Base):
    """Compliance frameworks (EU AI Act, NIST AI RMF, ISO 42001)"""
    __tablename__ = "frameworks"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    short_code = Column(String(20), nullable=False, unique=True)  # e.g., "eu-ai-act"
    version = Column(String(20))
    description = Column(Text)
    color = Column(String(7))  # Hex color for UI, e.g., "#3b82f6"
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    requirement_mappings = relationship("RequirementFrameworkMap", back_populates="framework")

# ===========================================
# NEW: Requirement-to-Framework Mapping
# ===========================================

class RequirementFrameworkMap(Base):
    """Maps requirements to frameworks (many-to-many)"""
    __tablename__ = "requirement_framework_map"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    requirement_id = Column(String(36), ForeignKey("compliance_requirements.id"), nullable=False)
    framework_id = Column(String(36), ForeignKey("frameworks.id"), nullable=False)
    article_ref = Column(String(50))  # e.g., "Art. 9" for EU AI Act, "MAP 1.1" for NIST
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    requirement = relationship("ComplianceRequirement", back_populates="framework_mappings")
    framework = relationship("Framework", back_populates="requirement_mappings")

# ===========================================
# NEW: Compliance Events (Activity Feed)
# ===========================================

class ComplianceEvent(Base):
    """Compliance events for activity feed"""
    __tablename__ = "compliance_events"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    system_id = Column(String(36), ForeignKey("ai_systems.id"), nullable=True)
    
    event_type = Column(Enum(EventType), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    severity = Column(Enum(EventSeverity), default=EventSeverity.INFO)
    
    # Store framework IDs as JSON array for flexibility
    framework_refs = Column(JSON, default=list)  # [{"framework_id": "...", "article_ref": "Art. 9"}]
    
    # Multi-tenant support (future)
    tenant_id = Column(String(36), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    ai_system = relationship("AISystem", back_populates="events")

# ===========================================
# EXISTING: AI System (updated with tenant_id)
# ===========================================

class AISystem(Base):
    """AI System being monitored for compliance"""
    __tablename__ = "ai_systems"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    description = Column(Text)
    risk_category = Column(Enum(RiskCategory), nullable=False)
    
    # Metadata
    organization = Column(String(255))
    department = Column(String(255))
    owner_email = Column(String(255))
    
    # Multi-tenant support (future)
    tenant_id = Column(String(36), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    requirements = relationship("RequirementMapping", back_populates="ai_system", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="ai_system", cascade="all, delete-orphan")
    events = relationship("ComplianceEvent", back_populates="ai_system")

# ===========================================
# EXISTING: Compliance Requirement (updated)
# ===========================================

class ComplianceRequirement(Base):
    """Compliance Requirements (can belong to multiple frameworks)"""
    __tablename__ = "compliance_requirements"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    article = Column(String(50), nullable=False)  # e.g., "Article 9"
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    
    # Applicable risk categories (for filtering)
    applies_to = Column(JSON)  # List of risk categories this requirement applies to
    
    # Multi-tenant support (future)
    tenant_id = Column(String(36), nullable=True)
    
    # Relationships
    mappings = relationship("RequirementMapping", back_populates="requirement")
    framework_mappings = relationship("RequirementFrameworkMap", back_populates="requirement")

# ===========================================
# EXISTING: Requirement Mapping (unchanged)
# ===========================================

class RequirementMapping(Base):
    """Maps requirements to AI systems with compliance status"""
    __tablename__ = "requirement_mappings"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ai_system_id = Column(String(36), ForeignKey("ai_systems.id"), nullable=False)
    requirement_id = Column(String(36), ForeignKey("compliance_requirements.id"), nullable=False)
    
    status = Column(Enum(ComplianceStatus), default=ComplianceStatus.NOT_STARTED)
    notes = Column(Text)
    updated_by = Column(String(255), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    ai_system = relationship("AISystem", back_populates="requirements")
    requirement = relationship("ComplianceRequirement", back_populates="mappings")
    evidence = relationship("Evidence", back_populates="requirement_mapping")

# ===========================================
# EXISTING: Evidence (unchanged)
# ===========================================

class Evidence(Base):
    """Evidence/documentation supporting compliance - stored in S3"""
    __tablename__ = "evidence"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ai_system_id = Column(String(36), ForeignKey("ai_systems.id"), nullable=False)
    requirement_mapping_id = Column(String(36), ForeignKey("requirement_mappings.id"), nullable=True)
    
    # File metadata (S3 storage)
    file_name = Column(String(255), nullable=False)
    file_type = Column(String(50), nullable=False)
    file_size = Column(Integer, nullable=False)
    s3_key = Column(String(500), nullable=False)
    
    # Legacy fields
    title = Column(String(255), nullable=True)
    file_url = Column(String(500), nullable=True)
    
    # Description
    description = Column(Text, nullable=True)
    
    # Evidence lifecycle
    status = Column(Enum(EvidenceStatus), default=EvidenceStatus.CURRENT)
    expiration_date = Column(Date, nullable=True)
    
    # Tracking
    uploaded_by = Column(String(255), nullable=True)
    
    # Soft delete
    deleted_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    ai_system = relationship("AISystem", back_populates="evidence")
    requirement_mapping = relationship("RequirementMapping", back_populates="evidence")
    
    