from models import Base, engine

# 🏗 Create all tables from models
Base.metadata.create_all(bind=engine)

print("✅ Tables created successfully.")
