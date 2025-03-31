from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext

# Initialize FastAPI app
app = FastAPI(title="Patient Management System")

# Security configurations
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Data models
class Patient(BaseModel):
    id: Optional[int] = None
    name: str = Field(..., min_length=2, max_length=50)
    age: int = Field(..., gt=0, lt=150)
    gender: str = Field(..., pattern="^(male|female|other)$")
    condition: str
    admission_date: datetime = Field(default_factory=datetime.now)

class User(BaseModel):
    username: str
    hashed_password: str

# Mock database
patients_db = {}
users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("admin123")
    }
}

# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in users_db:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return users_db[username]
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")

# API endpoints
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    token = jwt.encode(
        {"sub": user["username"], "exp": datetime.utcnow() + timedelta(minutes=30)},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return {"access_token": token, "token_type": "bearer"}

@app.post("/patients/", response_model=Patient, status_code=status.HTTP_201_CREATED)
async def create_patient(patient: Patient, current_user: User = Depends(get_current_user)):
    if patient.id in patients_db:
        raise HTTPException(status_code=400, detail="Patient ID already exists")
    patients_db[patient.id] = patient
    return patient

@app.get("/patients/", response_model=List[Patient])
async def read_patients(current_user: User = Depends(get_current_user)):
    return list(patients_db.values())

@app.get("/patients/{patient_id}", response_model=Patient)
async def read_patient(patient_id: int, current_user: User = Depends(get_current_user)):
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    return patients_db[patient_id]

@app.put("/patients/{patient_id}", response_model=Patient)
async def update_patient(
    patient_id: int, 
    patient: Patient, 
    current_user: User = Depends(get_current_user)
):
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    patient.id = patient_id
    patients_db[patient_id] = patient
    return patient

@app.delete("/patients/{patient_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_patient(patient_id: int, current_user: User = Depends(get_current_user)):
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    del patients_db[patient_id]
    return None