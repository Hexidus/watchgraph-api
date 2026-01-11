from sqlalchemy import Column, String, Integer, DateTime, Enum, ForeignKey, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
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
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    requirements = relationship("RequirementMapping", back_populates="ai_system", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="ai_system", cascade="all, delete-orphan")

class ComplianceRequirement(Base):
    """EU AI Act Compliance Requirements"""
    __tablename__ = "compliance_requirements"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    article = Column(String(50), nullable=False)  # e.g., "Article 9"
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    
    # Applicable risk categories
    applies_to = Column(JSON)  # List of risk categories this requirement applies to
    
    # Relationships
    mappings = relationship("RequirementMapping", back_populates="requirement")

class RequirementMapping(Base):
    """Maps requirements to AI systems with compliance status"""
    __tablename__ = "requirement_mappings"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ai_system_id = Column(String(36), ForeignKey("ai_systems.id"), nullable=False)
    requirement_id = Column(String(36), ForeignKey("compliance_requirements.id"), nullable=False)
    
    status = Column(Enum(ComplianceStatus), default=ComplianceStatus.NOT_STARTED)
    notes = Column(Text)
    updated_by = Column(String(255), nullable=True)  # Email of who updated it
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    ai_system = relationship("AISystem", back_populates="requirements")
    requirement = relationship("ComplianceRequirement", back_populates="mappings")
    evidence = relationship("Evidence", back_populates="requirement_mapping")

class Evidence(Base):
    """Evidence/documentation supporting compliance"""
    __tablename__ = "evidence"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ai_system_id = Column(String(36), ForeignKey("ai_systems.id"), nullable=False)
    requirement_mapping_id = Column(String(36), ForeignKey("requirement_mappings.id"))
    
    title = Column(String(255), nullable=False)
    description = Column(Text)
    file_url = Column(String(500))  # URL to stored file (Azure Blob Storage later)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    ai_system = relationship("AISystem", back_populates="evidence")
    requirement_mapping = relationship("RequirementMapping", back_populates="evidence")