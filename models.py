from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from app import db

class PrivateKey(db.Model):
    __tablename__ = 'private_keys'
    
    id = Column(Integer, primary_key=True)
    key = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_by = Column(String(255), nullable=True)
    usage_count = Column(Integer, default=0)
    max_usage = Column(Integer, nullable=True)
    description = Column(Text, nullable=True)
    
    def __repr__(self):
        return f'<PrivateKey {self.key}>'
    
    def is_valid(self):
        """Check if the key is still valid"""
        if not self.is_active:
            return False
        
        # Check expiration
        if self.expires_at is not None and datetime.utcnow() > self.expires_at:
            return False
        
        # Check usage limit
        if self.max_usage is not None and self.usage_count >= self.max_usage:
            return False
        
        return True

class AccessLog(db.Model):
    __tablename__ = 'access_logs'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(Text)
    location_data = Column(Text)
    device_info = Column(Text)
    accessed_script = Column(String(255))
    key_used = Column(String(64))
    timestamp = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, default=True)
    
    def __repr__(self):
        return f'<AccessLog {self.ip_address} - {self.timestamp}>'
