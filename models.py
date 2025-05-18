from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Database connection string (adjust your password if needed)
DATABASE_URL = "postgresql+psycopg2://postgres:postgres@localhost/password_tester"

# SQLAlchemy base and session setup
Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# ORM model representing the password_results table
class PasswordResult(Base):
    __tablename__ = 'password_results'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False)
    email = Column(String, nullable=False)  
    entropy = Column(Float, nullable=False)
    crack_time = Column(Text, nullable=False)
    strength = Column(String, nullable=False)
    feedback = Column(String)  # 🆕 Add this line to store full feedback
    submitted_at = Column(DateTime, default=datetime.utcnow)
