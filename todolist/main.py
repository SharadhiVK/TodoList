from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import mysql.connector
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

app = FastAPI()

# Database connection setup
mydb = mysql.connector.connect(
    host="localhost",
    user="yourusername",
    password="yourpassword",
    database="todo_db"
)
cursor = mydb.cursor()

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# User schema
class User(BaseModel):
    id: int
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

# Todo schema
class Todo(BaseModel):
    id: int
    title: str
    description: str
    completed: bool

# Authentication functions
def verify_password(plain_password, hashed_password):
    """
    Verify if the plain password matches the hashed password.

    Args:
        plain_password (str): Plain password.
        hashed_password (str): Hashed password.

    Returns:
        bool: True if the passwords match, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_user_by_email(email: str):
    """
    Retrieve a user record from the database by email.

    Args:
        email (str): User's email address.

    Returns:
        User: User object if found, None otherwise.
    """
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user_record = cursor.fetchone()
    if user_record:
        return User(id=user_record[0], username=user_record[1], email=user_record[2], full_name=user_record[3], disabled=user_record[4])

def authenticate_user(email: str, password: str):
    """
    Authenticate a user based on email and password.

    Args:
        email (str): User's email address.
        password (str): User's password.

    Returns:
        User: User object if authentication is successful, False otherwise.
    """
    user = get_user_by_email(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Token creation function
def create_access_token(data: dict):
    """
    Create an access token with the given data.

    Args:
        data (dict): Data to be encoded in the token.

    Returns:
        str: Generated access token.
    """
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Dependency to get the current user
def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Get the current authenticated user based on the provided token.

    Args:
        token (str): Access token obtained from the client.

    Returns:
        User: Current authenticated user.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(token_data.email)
    if user is None:
        raise credentials_exception
    return user

# Routes
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate a user and generate an access token.

    Args:
        form_data (OAuth2PasswordRequestForm): Form data containing username and password.

    Returns:
        dict: Dictionary containing access token and token type.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/todos/")
async def read_todos(skip: int = 0, limit: int = 10, current_user: User = Depends(get_current_user)):
    """
    Retrieve a list of To-do items for the current user.

    Args:
        skip (int): Number of items to skip (pagination).
        limit (int): Maximum number of items to retrieve (pagination).
        current_user (User): Current authenticated user.

    Returns:
        List[Todo]: List of Todo objects.
    """
    cursor.execute("SELECT * FROM todos WHERE user_id = %s LIMIT %s OFFSET %s", (current_user.id, limit, skip))
    todos_records = cursor.fetchall()
    todos = [Todo(id=record[0], title=record[1], description=record[2], completed=record[3]) for record in todos_records]
    return todos

@app.post("/todos/")
async def create_todo(todo: Todo, current_user: User = Depends(get_current_user)):
    """
    Create a new To-do item for the current user.

    Args:
        todo (Todo): To-do object containing title, description, and completion status.
        current_user (User): Current authenticated user.

    Returns:
        dict: Confirmation message.
    """
    cursor.execute("INSERT INTO todos (title, description, completed, user_id) VALUES (%s, %s, %s, %s)",
                   (todo.title, todo.description, todo.completed, current_user.id))
    mydb.commit()
    return {"message": "Todo created successfully"}

@app.put("/todos/{todo_id}")
async def update_todo(todo_id: int, todo: Todo, current_user: User = Depends(get_current_user)):
    """
    Update an existing To-do item for the current user.

    Args:
        todo_id (int): ID of the To-do item to be updated.
        todo (Todo): Updated To-do object.
        current_user (User): Current authenticated user.

    Returns:
        dict: Confirmation message.
    """
    cursor.execute("UPDATE todos SET title = %s, description = %s, completed = %s WHERE id = %s AND user_id = %s",
                   (todo.title, todo.description, todo.completed, todo_id, current_user.id))
    mydb.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"message": "Todo updated successfully"}

@app.delete("/todos/{todo_id}")
async def delete_todo(todo_id: int, current_user: User = Depends(get_current_user)):
    """
    Delete a To-do item for the current user.

    Args:
        todo_id (int): ID of the To-do item to be deleted.
        current_user (User): Current authenticated user
            Returns:
        dict: Confirmation message.
    """
    cursor.execute("DELETE FROM todos WHERE id = %s AND user_id = %s", (todo_id, current_user.id))
    mydb.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"message": "Todo deleted successfully"}

