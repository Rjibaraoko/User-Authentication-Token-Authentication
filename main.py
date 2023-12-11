from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt 
from passlib.context import CryptContext
import json
from typing import List
import hashlib


SECRET_KEY = "d20533cd538e0150032d080747aadfab53d5b01369dd2212134cc64e69c6f10b"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
USERS_DB_FILE = "users_db.json"


class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: str or None = None
    

class User(BaseModel):
    username: str
    email: str or None = None
    full_name: str or None = None
    disabled: bool or None = None
    
class UserInDB(User):
    hashed_password: str
    
class UserInRegister(UserInDB):
    password: str
    gender: str or None = None
    
class RegisterResponse(BaseModel):
    username: str
    email: str or None = None
    full_name: str or None = None
    gender: str or None = None
    
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)
    
    
def authenticate(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password_with_algorithm(password, user.hashed_password, "bcrypt"):
        return False
    
    return user


def create_access_token(data: dict, expires_delta: timedelta or None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() +timedelta (minutes=15)
        
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                         detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception
            
        token_data = TokenData(username = username)    
    except JWTError:
        raise credential_exception
    
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credential_exception
    
    return user

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
        
    return current_user

def save_db_to_file(db):
    with open(USERS_DB_FILE, "w") as file:
        json.dump(db, file)
        
def load_db_from_file():
    try:
        with open(USERS_DB_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return{}
    
#load db from file at start
db = load_db_from_file()

@app.on_event("shutdown")
def save_db_on_shutdown():
    #saves the data in the file after closing the application
    save_db_to_file(db)

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                            detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    access_token_expires =timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token= create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/user/me", response_model=User)
async def reader_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/user/me/items")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": 1, "owner":current_user}]

@app.post("/register", response_model=RegisterResponse)
async def register_user(user: UserInRegister):
# Perform registration logic here, for example, adding the new user to the database
# Should hash the password before saving it to the database
    new_user = {
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "gender": user.gender,
        "hashed_password": user.password, 
        "disabled": False
    }
    db[user.username] = new_user
    return new_user

@app.delete("/user/{username}/unauthenticated", response_model=dict)
async def delete_user(username: str):
    #checks if current user can be deleted by current user
    if username not in db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Username not found")
    
    del db[username]
    
    save_db_to_file(db)
    
    return {"message": "User deleted successfully"}
@app.get("/users", response_model=List[User])
async def get_all_users():
    return list(db.values())

def hash_password_with_sha256(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password_with_algorithm(plain_password, hashed_password, algorithm):
    if algorithm == "bcrypt":
        return pwd_context.verify(plain_password, hashed_password)
    elif algorithm == "sha256":
        # SHA-256 verification
        hashed_plain_password = hash_password_with_sha256(plain_password)
        return hashed_plain_password == hashed_password
    else:
        # Other algorithms if necessary
        return False
